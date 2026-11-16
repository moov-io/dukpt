package des

import (
	"bytes"
	"testing"

	"github.com/moov-io/dukpt/v2/pkg"
	"github.com/stretchr/testify/require"
)

// EncryptData pads a short IV to one block. It used to do it with append,
// which writes the zero padding into the caller's array when the IV slice has
// spare capacity.
func TestDataFunctions_DoNotModifyIV(t *testing.T) {
	tk := pkg.HexDecode("0DF3D9422ACA56E547676D07AD6BADFA")
	message := []byte("4012345678909D987")

	buf := bytes.Repeat([]byte{0xA5}, 8)
	iv := buf[:3]

	ciphertext, err := EncryptData(tk, iv, message, pkg.ActionRequest)
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{0xA5}, 8), buf, "EncryptData wrote into the IV's array")

	// DecryptData used to pass a short IV straight to cipher.NewCBCDecrypter,
	// which panics. It now pads the same way EncryptData does.
	plaintext, err := DecryptData(tk, ciphertext, iv, pkg.ActionRequest)
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{0xA5}, 8), buf, "DecryptData wrote into the IV's array")
	require.Equal(t, message, plaintext[:len(message)])
}

// An IV longer than a block is truncated by both functions. EncryptData used to
// pass it straight to cipher.NewCBCEncrypter, which panics.
func TestEncryptData_LongIV(t *testing.T) {
	tk := pkg.HexDecode("0DF3D9422ACA56E547676D07AD6BADFA")
	message := []byte("4012345678909D987")
	iv := bytes.Repeat([]byte{0x01}, 12)

	ciphertext, err := EncryptData(tk, iv, message, pkg.ActionRequest)
	require.NoError(t, err)
	viaBlock, err := EncryptData(tk, iv[:8], message, pkg.ActionRequest)
	require.NoError(t, err)
	require.Equal(t, viaBlock, ciphertext)

	plaintext, err := DecryptData(tk, ciphertext, iv, pkg.ActionRequest)
	require.NoError(t, err)
	require.Equal(t, message, plaintext[:len(message)])
}

// The KSN passed to the derivation functions is never modified.
func TestDerivation_DoesNotModifyKSN(t *testing.T) {
	bdk := pkg.HexDecode("0123456789ABCDEFFEDCBA9876543210")
	for _, ksnHex := range []string{"FFFF9876543210E00003", "9876543210E00003"} {
		ksn := pkg.HexDecode(ksnHex)
		want := bytes.Clone(ksn)
		ik, err := DerivationOfInitialKey(bdk, ksn)
		require.NoError(t, err)
		require.Equal(t, want, ksn)
		_, err = DeriveCurrentTransactionKey(ik, ksn)
		require.NoError(t, err)
		require.Equal(t, want, ksn)
	}
}
