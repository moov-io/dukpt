package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/chmike/cmac-go"
	"github.com/moov-io/dukpt/v2/encryption"
	"github.com/moov-io/dukpt/v2/pkg"
	"github.com/moov-io/pinblock/formats"
)

/*
ANSI X9.24-3-2017 (Retail Financial Services Symmetric Key Management)
*/

// ErrInvalidTransactionCounter is returned by DeriveCurrentTransactionKey when
// the KSN's transaction counter is not one a conforming terminal can use: zero,
// or with more than 16 bits set (see pkg.IsValidAesKsn).
//
// A counter of zero is the important case. The transaction key is derived by
// applying one derivation step per set counter bit, so a zero counter applies
// none and the "transaction key" is the Initial Key itself. Every function that
// takes the result (EncryptData, DecryptData, EncryptPin, DecryptPin,
// GenerateCMAC, GenerateHMAC) would then work directly under the Initial Key.
// A host that derives keys from a device-supplied KSN must not do that.
var ErrInvalidTransactionCounter = errors.New("invalid AES DUKPT transaction counter: zero or more than 16 bits set")

const (
	KeyAES128Type  = "AES128"
	KeyAES192Type  = "AES192"
	KeyAES256Type  = "AES256"
	KeyHMAC128Type = "HMAC128"
	KeyHMAC192Type = "HMAC192"
	KeyHMAC256Type = "HMAC256"
)

// Derive Initial Key (IK) from Base Derivative Key and Initial Key ID
//
// NOTE:
//   - ANSI X9.24-3-2017 6.3.1 Algorithm
//   - ANSI X9.24-3-2017 6.3.3 “Create Derivation Data” (Local Subroutine)
//
// Params:
//   - bdk is base derivative key (lenth will change by encryption algorithm)
//   - ksn is 12 bytes key serial number
//
// Return Params:
//   - reulst is initial key of bdk's length
//   - err
//
// The returned Initial Key belongs to the caller, who should clear it with
// dukpt.Clear once it is no longer needed. bdk and ksn are
// not modified, and no other copy of the Initial Key is left by this function.
func DerivationOfInitialKey(bdk, ksn []byte) ([]byte, error) {
	keyType, err := getDerivationKeyType(len(bdk))
	if err != nil {
		return nil, err
	}
	if len(ksn) < initialKeyIdLength {
		return nil, fmt.Errorf("ksn length must be at least %d bytes", initialKeyIdLength)
	}

	derivationData, err := createDerivationData(usageForKeyInitialKey, keyType, ksn[:8], 0)
	if err != nil {
		return nil, err
	}

	return derivationKey(bdk, derivationData)
}

// Derive DUKPT transaction key (current transaction key) from Initial Key and Key Serial Number
//
//	NOTE:
//	 - ANSI X9.24-3:2017 6.1, 6.3.1, 6.3.3
//
// Params:
//   - ik is initial key
//   - ksn is 12 bytes key serial number
//
// Return Params:
//   - result is transaction key of ik's length
//   - err wraps ErrInvalidTransactionCounter when the KSN's counter is zero or
//     has more than 16 bits set: a zero counter would return ik itself
//
// The returned transaction key belongs to the caller, who should clear it with
// dukpt.Clear once it is no longer needed. ik is not modified. Every intermediate derivation key
// is cleared as soon as the next one replaces it, including when an error is
// returned.
func DeriveCurrentTransactionKey(ik, ksn []byte) ([]byte, error) {
	keyType, err := getDerivationKeyType(len(ik))
	if err != nil {
		return nil, err
	}
	if !pkg.IsValidAesKsn(ksn) {
		return nil, fmt.Errorf("%w: %X", ErrInvalidTransactionCounter, pkg.GetAesTcFromKsn(ksn))
	}

	transactionKey := make([]byte, len(ik))
	copy(transactionKey, ik)

	tc := pkg.GetAesTcFromKsn(ksn)
	var workingTc uint32
	var derivationData *keyDerivationData

	for mask := uint32(0x80000000); mask != 0; mask >>= 1 {
		if tc&mask == 0 {
			continue
		}

		workingTc |= mask
		derivationData, err = createDerivationData(usageForKeyDerivation, keyType, ksn, workingTc)
		if err != nil {
			wipe(transactionKey)
			return nil, err
		}

		var nextKey []byte
		nextKey, err = derivationKey(transactionKey, derivationData)
		// The key just used is no longer needed, whether or not derivation
		// succeeded: this clears the copy of ik on the first pass and each
		// intermediate key after it.
		wipe(transactionKey)
		if err != nil {
			return nil, err
		}
		transactionKey = nextKey
	}

	return transactionKey, nil
}

// Encrypt PIN block using DUKPT transaction key
//
// NOTE:
//   - ANSI X9.24-3:2017 9.4.2
//   - Support only ISO 9564-1:2017 PIN block format 4
//
// Params:
//   - current key is 16 bytes transaction key
//   - ksn is 12 bytes key serial number
//   - pin is the PIN as ASCII decimal digits, 4 to 12 of them
//   - pan is the PAN as ASCII decimal digits, 12 to 19 of them
//   - key type is AES128, AES192, AES256
//
// Return Params:
//   - result is the 16-byte enciphered ISO-4 PIN block
//   - err
//
// The PIN encryption key derived from currentKey, and every intermediate of
// the PIN block, are cleared before returning. currentKey, pin and pan are not
// modified and stay the caller's to clear. No copy of the PIN is ever made as a
// string.
func EncryptPin(currentKey, ksn, pin, pan []byte, keyType string) ([]byte, error) {
	if err := checkWorkingKeyLength(len(currentKey), keyType); err != nil {
		return nil, err
	}

	pinKey, err := generateDerivationKey(derivationParams{
		KeyUsage:   usageForPinEncryption,
		KeyType:    keyType,
		Ksn:        ksn,
		CurrentKey: currentKey,
	})
	if err != nil {
		return nil, err
	}
	defer wipe(pinKey)

	cipher, err := encryption.NewAesECB(pinKey)
	if err != nil {
		return nil, err
	}

	return formats.NewISO4(cipher).Encode(pin, pan)
}

// Decrypt PIN block using DUKPT transaction key
//
// NOTE:
//   - ANSI X9.24-3:2017 9.4.2
//   - Support only ISO 9564-1:2017 PIN block format 4
//
// Params:
//   - current key is 16 bytes transaction key
//   - ksn is 12 bytes key serial number
//   - ciphertext is the 16-byte enciphered ISO-4 PIN block
//   - pan is the PAN as ASCII decimal digits, 12 to 19 of them
//   - key type is AES128, AES192, AES256
//
// Return Params:
//   - result is the PIN as ASCII decimal digits
//   - err
//
// The PIN encryption key derived from currentKey, and every intermediate of
// the PIN block, are cleared before returning. The returned PIN belongs to the
// caller, who should clear it with dukpt.Clear once it is no longer needed. No
// copy of the PIN is ever made as a string.
func DecryptPin(currentKey, ksn, ciphertext, pan []byte, keyType string) ([]byte, error) {
	if err := checkWorkingKeyLength(len(currentKey), keyType); err != nil {
		return nil, err
	}

	pinKey, err := generateDerivationKey(derivationParams{
		KeyUsage:   usageForPinEncryption,
		KeyType:    keyType,
		Ksn:        ksn,
		CurrentKey: currentKey,
	})
	if err != nil {
		return nil, err
	}
	defer wipe(pinKey)

	cipher, err := encryption.NewAesECB(pinKey)
	if err != nil {
		return nil, err
	}

	return formats.NewISO4(cipher).Decode(ciphertext, pan)
}

// Generate AES-CMAC for transaction request using transaction key
//
// NOTE:
//   - ANSI X9.24-3:2017 6.3.1, 6.3.4
//
// Params:
//   - current key is 16 bytes transaction key
//   - ksn is 12 bytes key serial number
//   - message is the data to authenticate
//   - key type is AES128, AES192, AES256
//   - action is request or response action
//
// Return Params:
//   - result is 16bytes generated cmac
//   - err
//
// The MAC key derived from currentKey is cleared before returning; currentKey
// is not modified and stays the caller's to clear. The CMAC's AES key schedule
// and subkeys are held inside crypto/aes and the CMAC implementation, which
// offer no way to clear them.
func GenerateCMAC(currentKey, ksn, message []byte, keyType string, action string) ([]byte, error) {
	if err := checkWorkingKeyLength(len(currentKey), keyType); err != nil {
		return nil, err
	}

	if action != pkg.ActionRequest && action != pkg.ActionResponse {
		action = pkg.ActionRequest
	}

	params := derivationParams{
		KeyUsage:   usageForMessageGeneration,
		KeyType:    keyType,
		Ksn:        ksn,
		CurrentKey: currentKey,
	}
	if action == pkg.ActionResponse {
		params.KeyUsage = usageForMessageVerification
	}

	macKey, err := generateDerivationKey(params)
	if err != nil {
		return nil, err
	}
	defer wipe(macKey)

	cm, err := cmac.New(aes.NewCipher, macKey)
	if err != nil {
		return nil, err
	}
	cm.Write(message)

	return cm.Sum(nil), nil
}

// Generate AES-CMAC for transaction request using transaction key
//
// NOTE:
//   - ANSI X9.24-3:2017 6.3.1, 6.3.4
//   - Support only HMAC 256
//
// Params:
//   - current key is 16 bytes transaction key
//   - ksn is 12 bytes key serial number
//   - message is the data to authenticate
//   - key type is AES128, AES192, AES256
//   - action is request or response action
//
// Return Params:
//   - result is 16bytes generated cmac
//   - err
//
// The MAC key derived from currentKey is cleared before returning; currentKey
// is not modified and stays the caller's to clear. crypto/hmac keeps its own
// padded copies of the key, which it offers no way to clear.
func GenerateHMAC(currentKey, ksn, message []byte, keyType string, action string) ([]byte, error) {
	if err := checkWorkingKeyLengthHmac(len(currentKey), keyType); err != nil {
		return nil, err
	}

	if action != pkg.ActionRequest && action != pkg.ActionResponse {
		action = pkg.ActionRequest
	}

	params := derivationParams{
		KeyUsage:   usageForMessageGeneration,
		KeyType:    keyType,
		Ksn:        ksn,
		CurrentKey: currentKey,
	}
	if action == pkg.ActionResponse {
		params.KeyUsage = usageForMessageVerification
	}

	macKey, err := generateDerivationKey(params)
	if err != nil {
		return nil, err
	}
	defer wipe(macKey)

	mac := hmac.New(sha256.New, macKey)
	mac.Write(message)

	return mac.Sum(nil), nil
}

// Encrypt Data using DUKPT transaction key
//
// NOTE:
//   - ANSI X9.24-3:2017 6.3.3, 6.5.4
//
// Params:
//   - current key is 16 bytes transaction key
//   - ksn is 12 bytes key serial number
//   - iv is initial vector
//   - plaintext is the data to encrypt, zero-padded to a multiple of 16 bytes
//   - key type is AES128, AES192, AES256
//   - action is request or response action
//
// Return Params:
//   - result is encrypted data
//   - err
//
// The data encryption key derived from currentKey, and the padded copy of
// plaintext, are cleared before returning; currentKey is not modified and stays
// the caller's to clear; plaintext is not modified and is also the caller's.
func EncryptData(currentKey, ksn, iv, plaintext []byte, keyType, action string) ([]byte, error) {
	if err := checkWorkingKeyLength(len(currentKey), keyType); err != nil {
		return nil, err
	}

	if action != pkg.ActionRequest && action != pkg.ActionResponse {
		action = pkg.ActionRequest
	}

	params := derivationParams{
		KeyUsage:   usageForDataEncrypt,
		KeyType:    keyType,
		Ksn:        ksn,
		CurrentKey: currentKey,
	}
	if action == pkg.ActionResponse {
		params.KeyUsage = usageForDataDecrypt
	}

	dataKey, err := generateDerivationKey(params)
	if err != nil {
		return nil, err
	}
	defer wipe(dataKey)

	if iv == nil {
		// default null
		iv = make([]byte, aes.BlockSize)
	}
	if len(iv) < aes.BlockSize {
		iv = append(iv, make([]byte, aes.BlockSize-len(iv))...)
	}

	repeatCnt := len(plaintext) / aes.BlockSize
	if len(plaintext)%aes.BlockSize > 0 {
		repeatCnt++
	}
	serializePlaintext := make([]byte, repeatCnt*aes.BlockSize)
	defer wipe(serializePlaintext)
	copy(serializePlaintext, plaintext)

	ciphertext := make([]byte, len(serializePlaintext))

	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, fmt.Errorf("making cipher from datakey: %w", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, serializePlaintext)

	return ciphertext, nil
}

// Decrypt Data using DUKPT transaction key
//
// NOTE:
//   - ANSI X9.24-3:2017 6.3.3, 6.5.4
//
// Params:
//   - current key is 16 bytes transaction key
//   - ksn is 12 bytes key serial number
//   - iv is initial vector
//   - cipher text is encrypted data
//   - key type is AES128, AES192, AES256
//   - action is request or response action
//
// Return Params:
//   - result is the decrypted data, a multiple of the AES block length (16
//     bytes); it includes any padding added before encryption
//   - err
//
// The data encryption key derived from currentKey is cleared before returning;
// currentKey is not modified and stays the caller's to clear. The result
// belongs to the caller, who should clear it with dukpt.Clear once the data is
// no longer needed.
func DecryptData(currentKey, ksn, ciphertext, iv []byte, keyType, action string) ([]byte, error) {
	if err := checkWorkingKeyLength(len(currentKey), keyType); err != nil {
		return nil, err
	}

	if action != pkg.ActionRequest && action != pkg.ActionResponse {
		action = pkg.ActionRequest
	}

	params := derivationParams{
		KeyUsage:   usageForDataEncrypt,
		KeyType:    keyType,
		Ksn:        ksn,
		CurrentKey: currentKey,
	}
	if action == pkg.ActionResponse {
		params.KeyUsage = usageForDataDecrypt
	}

	dataKey, err := generateDerivationKey(params)
	if err != nil {
		return nil, err
	}
	defer wipe(dataKey)

	if iv == nil {
		// default null
		iv = make([]byte, aes.BlockSize)
	}

	if len(iv) < aes.BlockSize {
		iv = append(iv, make([]byte, aes.BlockSize-len(iv))...)
	} else if len(iv) > aes.BlockSize {
		iv = iv[:aes.BlockSize]
	}

	repeatCnt := len(ciphertext) / aes.BlockSize
	if len(ciphertext)%aes.BlockSize > 0 {
		repeatCnt++
	}
	serializePlaintext := make([]byte, repeatCnt*aes.BlockSize)
	copy(serializePlaintext, ciphertext)

	plaintext := make([]byte, len(serializePlaintext))

	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, fmt.Errorf("making cipher from datakey: %w", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, serializePlaintext)

	return plaintext, nil
}
