package aes

import (
	"bytes"
	"testing"

	"github.com/moov-io/dukpt/v2/pkg"
	"github.com/stretchr/testify/require"
)

// wipeRecorder replaces the package's wipe hook for one test. It records what
// each buffer held just before it was cleared, and the buffer itself, so a test
// can check both that a given key was cleared and that the clear took effect.
type wipeRecorder struct {
	before  [][]byte
	buffers [][]byte
}

func recordWipes(t *testing.T) *wipeRecorder {
	t.Helper()
	r := &wipeRecorder{}
	original := wipe
	wipe = func(b []byte) {
		r.before = append(r.before, bytes.Clone(b))
		r.buffers = append(r.buffers, b)
		original(b)
	}
	t.Cleanup(func() { wipe = original })
	return r
}

// requireWiped fails unless some cleared buffer held exactly key.
func (r *wipeRecorder) requireWiped(t *testing.T, key []byte, name string) {
	t.Helper()
	for _, b := range r.before {
		if bytes.Equal(b, key) {
			return
		}
	}
	require.Failf(t, "key not cleared", "%s (%X) was never passed to wipe", name, key)
}

// requireAllZero fails unless every buffer passed to wipe is still all zero
// when the function under test has returned.
func (r *wipeRecorder) requireAllZero(t *testing.T) {
	t.Helper()
	require.NotEmpty(t, r.buffers)
	for i, b := range r.buffers {
		require.Equal(t, make([]byte, len(b)), b, "buffer %d is not zero after return", i)
	}
}

// The tests use AES-256 keys on purpose. An AES-128 key is a single encrypted
// block, so the block cleared inside derivationKey would hold the same bytes as
// the key itself and a test could not tell whether the caller cleared its copy.
// An AES-256 key is two blocks, so only the caller's clear matches the key.
var (
	wipeTestBDK = bytes.Repeat([]byte{0x5A}, 32)
	wipeTestIID = pkg.HexDecode("1234567890123456")
	// Counter 0x0B has three bits set, so derivation takes three steps and
	// leaves two intermediate keys between the Initial Key and the result.
	wipeTestKSN = pkg.HexDecode("12345678901234560000000B")
)

// wipeTestKey returns the Initial Key derived from wipeTestBDK, computed
// without the hook.
func wipeTestKey(t *testing.T) []byte {
	t.Helper()
	data, err := createDerivationData(usageForKeyInitialKey, KeyAES256Type, wipeTestIID, 0)
	require.NoError(t, err)
	ik, err := derivationKey(wipeTestBDK, data)
	require.NoError(t, err)
	require.Len(t, ik, 32)
	return ik
}

func TestDerivationOfInitialKey_ClearsBlocks(t *testing.T) {
	expected := wipeTestKey(t)

	r := recordWipes(t)
	bdk := bytes.Clone(wipeTestBDK)

	ik, err := DerivationOfInitialKey(bdk, wipeTestKSN)
	require.NoError(t, err)
	require.Equal(t, expected, ik)
	require.Equal(t, wipeTestBDK, bdk, "bdk must not be modified")

	// Each encrypted block is cleared once copied into the result.
	r.requireWiped(t, expected[:16], "first encrypted block")
	r.requireWiped(t, expected[16:], "second encrypted block")
	r.requireAllZero(t)
}

func TestDeriveCurrentTransactionKey_ClearsIntermediates(t *testing.T) {
	// The chain of keys, computed step by step without the hook.
	ik := wipeTestKey(t)
	tc := pkg.GetAesTcFromKsn(wipeTestKSN)
	chain := [][]byte{bytes.Clone(ik)}
	var workingTc uint32
	for mask := uint32(0x80000000); mask != 0; mask >>= 1 {
		if tc&mask == 0 {
			continue
		}
		workingTc |= mask
		data, err := createDerivationData(usageForKeyDerivation, KeyAES256Type, bytes.Clone(wipeTestKSN), workingTc)
		require.NoError(t, err)
		next, err := derivationKey(chain[len(chain)-1], data)
		require.NoError(t, err)
		chain = append(chain, next)
	}
	require.Len(t, chain, 4)

	r := recordWipes(t)

	key, err := DeriveCurrentTransactionKey(ik, wipeTestKSN)
	require.NoError(t, err)
	require.Equal(t, chain[len(chain)-1], key)
	require.Equal(t, chain[0], ik, "ik must not be modified")

	// The copy of ik and each intermediate key are cleared once replaced.
	for i, k := range chain[:len(chain)-1] {
		r.requireWiped(t, k, map[bool]string{true: "copy of ik", false: "intermediate key"}[i == 0])
	}
	r.requireAllZero(t)
}

func TestWorkingKeys_AreCleared(t *testing.T) {
	ksn := wipeTestKSN
	tk := bytes.Repeat([]byte{0xC3}, 32)
	message := []byte("4012345678909D987")

	workingKey := func(usage uint16, keyType string) []byte {
		k, err := generateDerivationKey(derivationParams{KeyUsage: usage, KeyType: keyType, Ksn: ksn, CurrentKey: tk})
		require.NoError(t, err)
		return k
	}

	encrypted, err := EncryptData(tk, ksn, nil, message, KeyAES256Type, pkg.ActionRequest)
	require.NoError(t, err)
	encryptedPin, err := EncryptPin(tk, ksn, []byte("1234"), []byte("4111111111111111"), KeyAES256Type)
	require.NoError(t, err)

	cases := []struct {
		name string
		key  []byte
		call func() error
	}{
		{"PIN key (EncryptPin)", workingKey(usageForPinEncryption, KeyAES256Type), func() error {
			_, err := EncryptPin(tk, ksn, []byte("1234"), []byte("4111111111111111"), KeyAES256Type)
			return err
		}},
		{"PIN key (DecryptPin)", workingKey(usageForPinEncryption, KeyAES256Type), func() error {
			_, err := DecryptPin(tk, ksn, encryptedPin, []byte("4111111111111111"), KeyAES256Type)
			return err
		}},
		{"CMAC request key", workingKey(usageForMessageGeneration, KeyAES256Type), func() error {
			_, err := GenerateCMAC(tk, ksn, message, KeyAES256Type, pkg.ActionRequest)
			return err
		}},
		{"CMAC response key", workingKey(usageForMessageVerification, KeyAES256Type), func() error {
			_, err := GenerateCMAC(tk, ksn, message, KeyAES256Type, pkg.ActionResponse)
			return err
		}},
		{"HMAC request key", workingKey(usageForMessageGeneration, KeyHMAC256Type), func() error {
			_, err := GenerateHMAC(tk, ksn, message, KeyHMAC256Type, pkg.ActionRequest)
			return err
		}},
		{"data key (EncryptData)", workingKey(usageForDataEncrypt, KeyAES256Type), func() error {
			_, err := EncryptData(tk, ksn, nil, message, KeyAES256Type, pkg.ActionRequest)
			return err
		}},
		{"data key (DecryptData)", workingKey(usageForDataEncrypt, KeyAES256Type), func() error {
			_, err := DecryptData(tk, ksn, encrypted, nil, KeyAES256Type, pkg.ActionRequest)
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := recordWipes(t)
			before := bytes.Clone(tk)
			require.NoError(t, c.call())
			r.requireWiped(t, c.key, c.name)
			r.requireAllZero(t)
			require.Equal(t, before, tk, "the transaction key must not be modified")
		})
	}
}

func TestEncryptData_ClearsPaddedPlaintext(t *testing.T) {
	ksn := wipeTestKSN
	tk := bytes.Repeat([]byte{0xC3}, 32)
	plaintext := []byte("4012345678909D987")
	padded := make([]byte, 32)
	copy(padded, plaintext)

	r := recordWipes(t)
	_, err := EncryptData(tk, ksn, nil, plaintext, KeyAES256Type, pkg.ActionRequest)
	require.NoError(t, err)
	r.requireWiped(t, padded, "padded plaintext")
	require.Equal(t, []byte("4012345678909D987"), plaintext, "plaintext must not be modified")
}

func TestDecryptData_ReturnsCallerOwnedBytes(t *testing.T) {
	ksn := wipeTestKSN
	tk := bytes.Repeat([]byte{0xC3}, 32)
	plaintext := []byte("4012345678909D987")

	encrypted, err := EncryptData(tk, ksn, nil, plaintext, KeyAES256Type, pkg.ActionRequest)
	require.NoError(t, err)

	decrypted, err := DecryptData(tk, ksn, encrypted, nil, KeyAES256Type, pkg.ActionRequest)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted[:len(plaintext)])

	// The result is not shared with anything the library keeps: clearing it
	// does not affect a second decryption.
	clear(decrypted)
	again, err := DecryptData(tk, ksn, encrypted, nil, KeyAES256Type, pkg.ActionRequest)
	require.NoError(t, err)
	require.Equal(t, plaintext, again[:len(plaintext)])
}

// The PIN functions take and return []byte: inputs are not modified and the
// PIN returned is the caller's.
func TestPinFunctions_ByteOwnership(t *testing.T) {
	tk := pkg.HexDecode("4F21B565BAD9835E112B6465635EAE44")
	ksn := pkg.HexDecode("123456789012345600000001")
	pin, pan := []byte("1234"), []byte("4111111111111111")

	encrypted, err := EncryptPin(tk, ksn, pin, pan, KeyAES128Type)
	require.NoError(t, err)
	require.Len(t, encrypted, 16)
	require.Equal(t, []byte("1234"), pin)
	require.Equal(t, []byte("4111111111111111"), pan)

	decrypted, err := DecryptPin(tk, ksn, encrypted, pan, KeyAES128Type)
	require.NoError(t, err)
	require.Equal(t, pin, decrypted)
	clear(decrypted)
	again, err := DecryptPin(tk, ksn, encrypted, pan, KeyAES128Type)
	require.NoError(t, err)
	require.Equal(t, pin, again)
}
