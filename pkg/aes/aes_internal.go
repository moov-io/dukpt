package aes

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"github.com/moov-io/dukpt/encryption"
	"github.com/moov-io/dukpt/pkg"
)

const (
	derivationKeyIdLength    = 4
	derivationIdLength       = 4
	initialKeyIdLength       = derivationKeyIdLength + derivationIdLength
	transactionCounterLength = 4
)

// Key types and bits for AES
//
//	6.2.1 and 6.2.2
const (
	keyTDES2Bits   = 0x0080
	keyTDES3Bits   = 0x00C0
	keyAES128Bits  = 0x0080
	keyAES192Bits  = 0x00C0
	keyAES256Bits  = 0x0100
	keyHMAC128Bits = 0x0080
	keyHMAC192Bits = 0x00C0
	keyHMAC256Bits = 0x0100
)

// Key indicators for AES
//
//	6.3.2 table 2 and table 3
const (
	derivationDataVersion = 0x01

	algorithmTwoKeyTDEA   = 0x0000
	algorithmThreeKeyTDEA = 0x0001
	algorithmAES128       = 0x0002
	algorithmAES192       = 0x0003
	algorithmAES256       = 0x0004
	algorithmHMAC         = 0x0005

	usageForKeyEncryption         = 0x0002
	usageForPinEncryption         = 0x1000
	usageForMessageGeneration     = 0x2000
	usageForMessageVerification   = 0x2001
	usageForMessageAuthentication = 0x2002
	usageForDataEncrypt           = 0x3000
	usageForDataDecrypt           = 0x3001
	usageForDataEncryption        = 0x3002
	usageForKeyDerivation         = 0x8000
	usageForKeyInitialKey         = 0x8001
)

const (
	keyTDES2Type   = "TDES2"
	keyTDES3Type   = "TDES3"
	keyHMAC128Type = "HMAC128"
	keyHMAC192Type = "HMAC192"
	keyHMAC256Type = "HMAC256"
)

// Key Derivation Data
//
//	6.3.2 Derivation Data
//	Table 2 - Terminal Key Derivation Data
type keyDerivationData struct {
	Version            byte
	KeyBlockCounter    byte
	KeyUsageIndicator  uint16
	AlgorithmIndicator uint16
	Length             uint16
	InitialKeyID       []byte
}

func (k *keyDerivationData) Bytes() []byte {
	if k == nil {
		return nil
	}

	var result []byte
	b := make([]byte, 2)

	result = append(result, k.Version)
	result = append(result, k.KeyBlockCounter)
	{
		binary.BigEndian.PutUint16(b, k.KeyUsageIndicator)
		result = append(result, b...)
	}
	{
		binary.BigEndian.PutUint16(b, k.AlgorithmIndicator)
		result = append(result, b...)
	}
	{
		binary.BigEndian.PutUint16(b, k.Length)
		result = append(result, b...)
	}
	result = append(result, k.InitialKeyID...)

	return result
}

type derivationParams struct {
	KeyUsage   uint16
	KeyType    string
	Ksn        []byte
	CurrentKey []byte
}

func getDerivationKeyType(keyLen int) (string, error) {
	switch keyLen {
	case keyAES128Bits / 8:
		return KeyAES128Type, nil
	case keyAES192Bits / 8:
		return KeyAES192Type, nil
	case keyAES256Bits / 8:
		return KeyAES256Type, nil
	}
	return "", errors.New("unsupported key length yet")
}

func derivationKey(key []byte, derivationData *keyDerivationData) ([]byte, error) {
	var derivedKey []byte
	derivedKeyLen := int(derivationData.Length / 8)

	aesEcb, err := encryption.NewAesECB(key)
	if err != nil {
		return nil, err
	}

	for offset := 0; offset < derivedKeyLen; offset += aes.BlockSize {
		data := derivationData.Bytes()
		encrypted, encErr := aesEcb.Encrypt(data)
		if encErr != nil {
			return nil, encErr
		}
		derivedKey = append(derivedKey, encrypted...)
		derivationData.KeyBlockCounter++
	}

	return derivedKey, nil
}

// Create key derivation data
//
//	6.3.3 “Create Derivation Data” (Local Subroutine)
func createDerivationData(keyUsage uint16, keyType string, initialKeyID []byte, tc uint32) (*keyDerivationData, error) {
	data := keyDerivationData{
		Version:           derivationDataVersion,
		KeyBlockCounter:   0x01,
		KeyUsageIndicator: keyUsage,
	}

	switch keyType {
	case keyTDES2Type:
		data.AlgorithmIndicator = algorithmTwoKeyTDEA
		data.Length = keyTDES2Bits
	case keyTDES3Type:
		data.AlgorithmIndicator = algorithmThreeKeyTDEA
		data.Length = keyTDES3Bits
	case KeyAES128Type:
		data.AlgorithmIndicator = algorithmAES128
		data.Length = keyAES128Bits
	case KeyAES192Type:
		data.AlgorithmIndicator = algorithmAES192
		data.Length = keyAES192Bits
	case KeyAES256Type:
		data.AlgorithmIndicator = algorithmAES256
		data.Length = keyAES256Bits
	case keyHMAC128Type:
		data.AlgorithmIndicator = algorithmHMAC
		data.Length = keyHMAC128Bits
	case keyHMAC192Type:
		data.AlgorithmIndicator = algorithmHMAC
		data.Length = keyHMAC192Bits
	case keyHMAC256Type:
		data.AlgorithmIndicator = algorithmHMAC
		data.Length = keyHMAC256Bits
	default:
		return nil, errors.New("unsupported key type")
	}

	switch keyUsage {
	case usageForKeyInitialKey:
		data.InitialKeyID = make([]byte, initialKeyIdLength)
		copy(data.InitialKeyID, initialKeyID)
	default:
		tcBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(tcBuf, tc)
		data.InitialKeyID = append(initialKeyID[derivationKeyIdLength:derivationKeyIdLength+derivationIdLength], tcBuf...)
	}

	return &data, nil
}

func checkWorkingKeyLengthHmac(keyLen uint16, keyType string) error {
	// Validate transaction/intermediate key length
	if keyLen != keyHMAC128Bits/8 &&
		keyLen != keyHMAC192Bits/8 &&
		keyLen != keyHMAC256Bits/8 {
		return errors.New("invalid current transaction key length")
	}

	var workingKeyLength uint16
	switch keyType {
	case keyHMAC128Type:
		workingKeyLength = keyHMAC128Bits / 8
	case keyHMAC192Type:
		workingKeyLength = keyHMAC192Bits / 8
	case keyHMAC256Type:
		workingKeyLength = keyHMAC256Bits / 8
	default:
		return errors.New("unsupported key type")
	}

	if keyLen != workingKeyLength {
		return errors.New("mismatched key length and key type")
	}

	return nil
}

func checkWorkingKeyLength(keyLen uint16, keyType string) error {
	// Validate transaction/intermediate key length
	if keyLen != keyAES128Bits/8 &&
		keyLen != keyAES192Bits/8 &&
		keyLen != keyAES256Bits/8 {
		return errors.New("invalid current transaction key length")
	}

	var workingKeyLength uint16
	switch keyType {
	case KeyAES128Type:
		workingKeyLength = keyAES128Bits / 8
	case KeyAES192Type:
		workingKeyLength = keyAES192Bits / 8
	case KeyAES256Type:
		workingKeyLength = keyAES256Bits / 8
	default:
		return errors.New("unsupported key type")
	}

	if keyLen != workingKeyLength {
		return errors.New("mismatched key length and key type")
	}

	return nil
}

func generateDerivationKey(params derivationParams) ([]byte, error) {
	tc := pkg.GetAesTcFromKsn(params.Ksn)
	derivationData, err := createDerivationData(params.KeyUsage, params.KeyType, params.Ksn, tc)
	if err != nil {
		return nil, err
	}

	newKey, err := derivationKey(params.CurrentKey, derivationData)
	if err != nil {
		return nil, err
	}

	return newKey, nil
}
