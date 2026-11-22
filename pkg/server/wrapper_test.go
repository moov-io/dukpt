package server

import (
	"testing"

	"github.com/moov-io/dukpt/pkg"
	"github.com/moov-io/dukpt/pkg/aes"

	"github.com/stretchr/testify/require"
)

func TestUnifiedParams_normalize(t *testing.T) {
	p := UnifiedParams{Algorithm: " AES ", AlgorithmKey: "aes192"}.normalize()
	require.Equal(t, pkg.AlgorithmAes, p.Algorithm)
	require.Equal(t, aes.KeyAES192Type, p.AlgorithmKey)

	// AES defaults to AES128
	p = UnifiedParams{Algorithm: "aes"}.normalize()
	require.Equal(t, aes.KeyAES128Type, p.AlgorithmKey)

	// HMAC uses the HMAC key type of the same length
	p = UnifiedParams{Algorithm: "aes", AlgorithmKey: "aes256", MacType: "HMAC"}.normalize()
	require.Equal(t, aes.KeyHMAC256Type, p.AlgorithmKey)
	require.Equal(t, pkg.MaxTypeHmac, p.MacType)

	// CMAC uses the AES key type of the same length
	p = UnifiedParams{Algorithm: "aes", AlgorithmKey: "hmac128", MacType: "cmac"}.normalize()
	require.Equal(t, aes.KeyAES128Type, p.AlgorithmKey)

	// DES does not set a key type
	p = UnifiedParams{Algorithm: "DES"}.normalize()
	require.Equal(t, pkg.AlgorithmDes, p.Algorithm)
	require.Equal(t, "", p.AlgorithmKey)

	require.NoError(t, UnifiedParams{Algorithm: "AES"}.ValidateAlgorithm())
	require.Error(t, UnifiedParams{Algorithm: "rsa"}.ValidateAlgorithm())
}

func TestWrapper_InvalidHex(t *testing.T) {
	_, err := InitialKey(UnifiedParams{Algorithm: "des", BKD: "zz", KSN: "FFFF9876543210E00001"})
	require.ErrorContains(t, err, "invalid hex value for bdk")

	_, err = TransactionKey(UnifiedParams{Algorithm: "des", IK: "00", KSN: "xyz"})
	require.ErrorContains(t, err, "invalid hex value for ksn")

	_, err = EncryptPin(UnifiedParams{Algorithm: "des", TK: "q"})
	require.ErrorContains(t, err, "invalid hex value for tk")

	_, err = DecryptPin(UnifiedParams{Algorithm: "des", TK: "00", PIN: "g"})
	require.ErrorContains(t, err, "invalid hex value for pin")

	_, err = GenerateMac(UnifiedParams{Algorithm: "aes", TK: "00", KSN: "g", MacType: "cmac"})
	require.ErrorContains(t, err, "invalid hex value for ksn")

	_, err = EncryptData(UnifiedParams{Algorithm: "des", TK: "00", IV: "g"})
	require.ErrorContains(t, err, "invalid hex value for iv")

	_, err = DecryptData(UnifiedParams{Algorithm: "des", TK: "00", Ciphertext: "g"})
	require.ErrorContains(t, err, "invalid hex value for ciphertext")
}

func TestWrapper_AesCaseInsensitive(t *testing.T) {
	ksn := "123456789012345600000001"
	ik, err := InitialKey(UnifiedParams{Algorithm: "AES", BKD: "FEDCBA9876543210F1F1F1F1F1F1F1F1", KSN: ksn})
	require.NoError(t, err)
	require.Equal(t, "1273671ea26ac29afa4d1084127652a1", ik)

	tk, err := TransactionKey(UnifiedParams{Algorithm: "aes", IK: ik, KSN: ksn})
	require.NoError(t, err)

	// lower case and empty key types work
	for _, keyType := range []string{"", "aes128", "AES128"} {
		enc, err := EncryptPin(UnifiedParams{Algorithm: "aes", AlgorithmKey: keyType, TK: tk, KSN: ksn, PIN: "1234", PAN: "4111111111111111"})
		require.NoError(t, err, keyType)

		pin, err := DecryptPin(UnifiedParams{Algorithm: "aes", AlgorithmKey: keyType, TK: tk, KSN: ksn, PIN: enc, PAN: "4111111111111111"})
		require.NoError(t, err, keyType)
		require.Equal(t, "1234", pin)
	}

	// HMAC with an AES key type
	hmac1, err := GenerateMac(UnifiedParams{Algorithm: "aes", AlgorithmKey: "aes128", MacType: "hmac", TK: tk, KSN: ksn, Plaintext: "hello", Action: pkg.ActionRequest})
	require.NoError(t, err)
	hmac2, err := GenerateMac(UnifiedParams{Algorithm: "aes", AlgorithmKey: "HMAC128", MacType: "hmac", TK: tk, KSN: ksn, Plaintext: "hello", Action: pkg.ActionRequest})
	require.NoError(t, err)
	require.Equal(t, hmac1, hmac2)

	enc, err := EncryptData(UnifiedParams{Algorithm: "aes", TK: tk, KSN: ksn, IV: "00000000000000000000000000000000", Plaintext: "hello", Action: pkg.ActionRequest})
	require.NoError(t, err)
	dec, err := DecryptData(UnifiedParams{Algorithm: "aes", TK: tk, KSN: ksn, IV: "00000000000000000000000000000000", Ciphertext: enc, Action: pkg.ActionRequest})
	require.NoError(t, err)
	require.Contains(t, dec, "hello")
}
