package aes

import (
	"bytes"
	"sync"
	"testing"

	"github.com/moov-io/dukpt/pkg"
	"github.com/stretchr/testify/require"
)

// createDerivationData must build the derivation data in its own buffer. It
// used to append the counter to initialKeyID[4:8], which for a 12-byte KSN
// writes the counter into the KSN's own last four bytes.
func TestCreateDerivationData_DoesNotModifyInput(t *testing.T) {
	ksn := pkg.HexDecode("12345678901234560000000B")
	want := bytes.Clone(ksn)

	data, err := createDerivationData(usageForKeyDerivation, KeyAES128Type, ksn, 0x08)
	require.NoError(t, err)
	require.Equal(t, want, ksn, "the KSN passed in must not be modified")
	require.Equal(t, pkg.HexDecode("9012345600000008"), data.InitialKeyID)

	data, err = createDerivationData(usageForKeyInitialKey, KeyAES128Type, ksn, 0)
	require.NoError(t, err)
	require.Equal(t, want, ksn)
	require.Equal(t, want[:8], data.InitialKeyID)

	// The derivation data does not share the caller's array either.
	data.InitialKeyID[0] ^= 0xFF
	require.Equal(t, want, ksn)
}

// A KSN longer than 12 bytes carries its counter in the last four bytes, so the
// old append wrote the intermediate counters over bytes 8..11, which are not the
// counter, and left them changed.
func TestDeriveCurrentTransactionKey_DoesNotModifyKSN(t *testing.T) {
	ik := pkg.HexDecode("1273671EA26AC29AFA4D1084127652A1")
	for _, ksnHex := range []string{
		"12345678901234560000000B",
		"1234567890123456AABBCCDD0000000B",
	} {
		ksn := pkg.HexDecode(ksnHex)
		want := bytes.Clone(ksn)

		_, err := DeriveCurrentTransactionKey(ik, ksn)
		require.NoError(t, err)
		require.Equal(t, want, ksn, "KSN %s", ksnHex)

		_, err = GenerateCMAC(pkg.HexDecode("4F21B565BAD9835E112B6465635EAE44"), ksn, "data", KeyAES128Type, pkg.ActionRequest)
		require.NoError(t, err)
		require.Equal(t, want, ksn, "KSN %s", ksnHex)
	}
}

// Many goroutines deriving from one shared KSN slice must not race. Under
// `go test -race` the old code fails here: every derivation wrote the KSN's
// counter bytes while the others read them.
func TestDeriveCurrentTransactionKey_ConcurrentSharedKSN(t *testing.T) {
	ik := pkg.HexDecode("1273671EA26AC29AFA4D1084127652A1")
	ksn := pkg.HexDecode("12345678901234560000000B")
	want, err := DeriveCurrentTransactionKey(ik, bytes.Clone(ksn))
	require.NoError(t, err)

	var wg sync.WaitGroup
	keys := make([][]byte, 16)
	errs := make([]error, len(keys))
	for i := range keys {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys[i], errs[i] = DeriveCurrentTransactionKey(ik, ksn)
		}()
	}
	wg.Wait()
	for i := range keys {
		require.NoError(t, errs[i])
		require.Equal(t, want, keys[i])
	}
}

// EncryptData and DecryptData pad a short IV to one block. They used to do it
// with append, which writes the zero padding into the caller's array when the
// IV slice has spare capacity.
func TestDataFunctions_DoNotModifyIV(t *testing.T) {
	tk := pkg.HexDecode("4F21B565BAD9835E112B6465635EAE44")
	ksn := pkg.HexDecode("123456789012345600000001")
	message := "4012345678909D987"

	buf := bytes.Repeat([]byte{0xA5}, 16)
	iv := buf[:4]

	ciphertext, err := EncryptData(tk, ksn, iv, message, KeyAES128Type, pkg.ActionRequest)
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{0xA5}, 16), buf, "EncryptData wrote into the IV's array")

	plaintext, err := DecryptData(tk, ksn, ciphertext, iv, KeyAES128Type, pkg.ActionRequest)
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{0xA5}, 16), buf, "DecryptData wrote into the IV's array")
	require.Equal(t, message, plaintext[:len(message)])
}

// An IV longer than a block is truncated by both functions. EncryptData used to
// pass it straight to cipher.NewCBCEncrypter, which panics.
func TestEncryptData_LongIV(t *testing.T) {
	tk := pkg.HexDecode("4F21B565BAD9835E112B6465635EAE44")
	ksn := pkg.HexDecode("123456789012345600000001")
	message := "4012345678909D987"
	iv := bytes.Repeat([]byte{0x01}, 20)

	ciphertext, err := EncryptData(tk, ksn, iv, message, KeyAES128Type, pkg.ActionRequest)
	require.NoError(t, err)
	viaBlock, err := EncryptData(tk, ksn, iv[:16], message, KeyAES128Type, pkg.ActionRequest)
	require.NoError(t, err)
	require.Equal(t, viaBlock, ciphertext)

	plaintext, err := DecryptData(tk, ksn, ciphertext, iv, KeyAES128Type, pkg.ActionRequest)
	require.NoError(t, err)
	require.Equal(t, message, plaintext[:len(message)])
}
