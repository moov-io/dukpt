package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/chmike/cmac-go"
	"github.com/moov-io/dukpt/encryption"
	"github.com/moov-io/dukpt/pkg"
	"github.com/moov-io/pinblock/formats"
)

/*
ANSI X9.24-3-2017 (Retail Financial Services Symmetric Key Management)
*/

const (
	KeyAES128Type = "AES128"
	KeyAES192Type = "AES192"
	KeyAES256Type = "AES256"
)

// Derive Initial Key (IK) from Base Derivative Key and Initial Key ID
//
// NOTE:
//   - ANSI X9.24-3-2017 6.3.1 Algorithm
//   - ANSI X9.24-3-2017 6.3.3 “Create Derivation Data” (Local Subroutine)
//
// Params:
//   - bdk is base derivative key (lenth will change by encryption algorithm)
//   - kid is 8 bytes initial key id
//
// Return Params:
//   - reulst is initial key of bdk's length
//   - err
func DerivationOfInitialKey(bdk, kid []byte) ([]byte, error) {
	keyType, err := getDerivationKeyType(len(bdk))
	if err != nil {
		return nil, err
	}

	derivationData, err := createDerivationData(usageForKeyInitialKey, keyType, kid, 0)
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
//   - err
func DeriveCurrentTransactionKey(ik, ksn []byte) ([]byte, error) {
	keyType, err := getDerivationKeyType(len(ik))
	if err != nil {
		return nil, err
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
			return nil, err
		}

		transactionKey, err = derivationKey(transactionKey, derivationData)
		if err != nil {
			return nil, err
		}
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
//   - pin is not formatted pin string
//   - pan is not formatted pan string
//   - key type is AES128, AES192, AES256
//
// Return Params:
//   - result is cipher text
//   - err
func EncryptPin(currentKey, ksn []byte, pin, pan string, keyType string) ([]byte, error) {
	if err := checkWorkingKeyLength(uint16(len(currentKey)), keyType); err != nil {
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

	cipher, err := encryption.NewAesECB(pinKey)
	if err != nil {
		return nil, err
	}

	formatter := formats.NewISO4(cipher)
	blockstr, err := formatter.Encode(pin, pan)
	if err != nil {
		return nil, err
	}

	return pkg.HexDecode(blockstr), nil
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
//   - pin is not formatted pin string
//   - pan is not formatted pan string
//   - key type is AES128, AES192, AES256
//
// Return Params:
//   - result is plain text
//   - err
func DecryptPin(currentKey, ksn, ciphertext []byte, pan string, keyType string) (string, error) {
	if err := checkWorkingKeyLength(uint16(len(currentKey)), keyType); err != nil {
		return "", err
	}

	pinKey, err := generateDerivationKey(derivationParams{
		KeyUsage:   usageForPinEncryption,
		KeyType:    keyType,
		Ksn:        ksn,
		CurrentKey: currentKey,
	})
	if err != nil {
		return "", err
	}

	cipher, err := encryption.NewAesECB(pinKey)
	if err != nil {
		return "", err
	}

	formatter := formats.NewISO4(cipher)
	blockstr, err := formatter.Decode(pkg.HexEncode(ciphertext), pan)
	if err != nil {
		return "", err
	}

	return blockstr, nil
}

// Generate AES-CMAC for transaction request using transaction key
//
// NOTE:
//   - ANSI X9.24-3:2017 6.3.1, 6.3.4
//
// Params:
//   - current key is 16 bytes transaction key
//   - ksn is 12 bytes key serial number
//   - plain text is transaction request data
//   - key type is AES128, AES192, AES256
//   - action is request or response action
//
// Return Params:
//   - result is 16bytes generated cmac
//   - err
func GenerateCMAC(currentKey, ksn []byte, plaintext string, keyType string, action string) ([]byte, error) {
	if err := checkWorkingKeyLength(uint16(len(currentKey)), keyType); err != nil {
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

	cm, err := cmac.New(aes.NewCipher, macKey)
	if err != nil {
		return nil, err
	}
	cm.Write([]byte(plaintext))

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
//   - plain text is transaction request data
//   - key type is AES128, AES192, AES256
//   - action is request or response action
//
// Return Params:
//   - result is 16bytes generated cmac
//   - err
func GenerateHMAC(currentKey, ksn []byte, plaintext string, keyType string, action string) ([]byte, error) {
	if err := checkWorkingKeyLengthHmac(uint16(len(currentKey)), keyType); err != nil {
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

	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte(plaintext))

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
//   - plain text is transaction request data
//   - key type is AES128, AES192, AES256
//   - action is request or response action
//
// Return Params:
//   - result is encrypted data
//   - err
func EncryptData(currentKey, ksn, iv []byte, plaintext, keyType, action string) ([]byte, error) {
	if err := checkWorkingKeyLength(uint16(len(currentKey)), keyType); err != nil {
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
//   - result is transaction request data ( must be a multiple of aes block length [16])
//   - err
func DecryptData(currentKey, ksn, iv, ciphertext []byte, keyType, action string) (string, error) {
	if err := checkWorkingKeyLength(uint16(len(currentKey)), keyType); err != nil {
		return "", err
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
		return "", err
	}

	if iv == nil {
		// default null
		iv = make([]byte, aes.BlockSize)
	}
	if len(iv) < aes.BlockSize {
		iv = append(iv, make([]byte, aes.BlockSize-len(iv))...)
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
		return "", fmt.Errorf("making cipher from datakey: %w", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, serializePlaintext)

	return string(plaintext), nil
}
