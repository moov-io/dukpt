package aes

import (
	"bytes"
	"testing"

	"github.com/moov-io/dukpt/pkg"
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
	message := "4012345678909D987"
	// v1 takes the message as a string; the byte copy the library makes of it
	// is cleared.
	messageCopy := []byte(message)
	padded := make([]byte, 32)
	copy(padded, message)

	workingKey := func(usage uint16, keyType string) []byte {
		k, err := generateDerivationKey(derivationParams{KeyUsage: usage, KeyType: keyType, Ksn: ksn, CurrentKey: tk})
		require.NoError(t, err)
		return k
	}

	encrypted, err := EncryptData(tk, ksn, nil, message, KeyAES256Type, pkg.ActionRequest)
	require.NoError(t, err)
	encryptedPin, err := EncryptPin(tk, ksn, "1234", "4111111111111111", KeyAES256Type)
	require.NoError(t, err)

	cases := []struct {
		name string
		want map[string][]byte
		call func() error
	}{
		{"EncryptPin", map[string][]byte{
			"PIN key": workingKey(usageForPinEncryption, KeyAES256Type),
		}, func() error {
			_, err := EncryptPin(tk, ksn, "1234", "4111111111111111", KeyAES256Type)
			return err
		}},
		{"DecryptPin", map[string][]byte{
			"PIN key": workingKey(usageForPinEncryption, KeyAES256Type),
		}, func() error {
			_, err := DecryptPin(tk, ksn, encryptedPin, "4111111111111111", KeyAES256Type)
			return err
		}},
		{"GenerateCMAC request", map[string][]byte{
			"CMAC request key": workingKey(usageForMessageGeneration, KeyAES256Type),
			"message copy":     messageCopy,
		}, func() error {
			_, err := GenerateCMAC(tk, ksn, message, KeyAES256Type, pkg.ActionRequest)
			return err
		}},
		{"GenerateCMAC response", map[string][]byte{
			"CMAC response key": workingKey(usageForMessageVerification, KeyAES256Type),
			"message copy":      messageCopy,
		}, func() error {
			_, err := GenerateCMAC(tk, ksn, message, KeyAES256Type, pkg.ActionResponse)
			return err
		}},
		{"GenerateHMAC request", map[string][]byte{
			"HMAC request key": workingKey(usageForMessageGeneration, KeyHMAC256Type),
			"message copy":     messageCopy,
		}, func() error {
			_, err := GenerateHMAC(tk, ksn, message, KeyHMAC256Type, pkg.ActionRequest)
			return err
		}},
		{"EncryptData", map[string][]byte{
			"data key":         workingKey(usageForDataEncrypt, KeyAES256Type),
			"padded plaintext": padded,
		}, func() error {
			_, err := EncryptData(tk, ksn, nil, message, KeyAES256Type, pkg.ActionRequest)
			return err
		}},
		{"DecryptData", map[string][]byte{
			"data key":        workingKey(usageForDataEncrypt, KeyAES256Type),
			"decrypted bytes": padded,
		}, func() error {
			_, err := DecryptData(tk, ksn, encrypted, nil, KeyAES256Type, pkg.ActionRequest)
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := recordWipes(t)
			before := bytes.Clone(tk)
			require.NoError(t, c.call())
			for name, value := range c.want {
				r.requireWiped(t, value, name)
			}
			r.requireAllZero(t)
			require.Equal(t, before, tk, "the transaction key must not be modified")
		})
	}
}

func TestDecryptData_ResultSurvivesClear(t *testing.T) {
	ksn := wipeTestKSN
	tk := bytes.Repeat([]byte{0xC3}, 32)
	plaintext := "4012345678909D987"
	padded := make([]byte, 32)
	copy(padded, plaintext)

	encrypted, err := EncryptData(tk, ksn, nil, plaintext, KeyAES256Type, pkg.ActionRequest)
	require.NoError(t, err)

	// The decrypted bytes are cleared before DecryptData returns, so the
	// returned string must have been copied from them first.
	r := recordWipes(t)
	decrypted, err := DecryptData(tk, ksn, encrypted, nil, KeyAES256Type, pkg.ActionRequest)
	require.NoError(t, err)
	r.requireWiped(t, padded, "decrypted bytes")
	require.Equal(t, string(padded), decrypted)
}
