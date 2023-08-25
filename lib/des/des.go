package des

/*
ANS X9.24-1:2009 (Retail Financial Services Symmetric Key Management)
*/

import (
	"crypto/cipher"
	"fmt"
	"strings"

	"github.com/moov-io/dukpt/encryption"
	"github.com/moov-io/dukpt/lib"
	"github.com/moov-io/pinblock/formats"
)

const (
	KeyLen       = 16
	KeySerialLen = 10
	TCBits       = 21
	DesBlockLen  = 8

	ActionDefault  = "request"
	ActionRequest  = "request"
	ActionResponse = "response"
)

// ANSI X9.24-1:2009 A.6 Derivation of the Initial Key
// ANSI X9.24-3:2017 C.7 "Security Module" Algorithm For Automatic PIN Entry Device Checking
//
//	ksn is 10 bytes key serial number
//	bdk is 16 bytes base derivative Key
//	restult is 16 bytes initial key
func DerivationOfInitialKey(bdk, ksn []byte) ([]byte, error) {
	if len(bdk) != KeyLen {
		return nil, fmt.Errorf("base derivative key length must be %d bytes", KeyLen)
	}

	ksnBytes := serializeKeySerialNumber(ksn)
	removeTransactionCounter(ksnBytes)

	leftCipher, _ := encryption.NewTripleDesECB(bdk)
	leftHalf, err := leftCipher.Encrypt(ksnBytes[:KeyLen/2])
	if err != nil {
		return nil, err
	}

	bdkVariant := make([]byte, len(bdk))
	copy(bdkVariant, bdk)
	serializeKeyWithHexadecimal(bdkVariant)

	rightCipher, _ := encryption.NewTripleDesECB(bdkVariant)
	rightHalf, err := rightCipher.Encrypt(ksnBytes[:KeyLen/2])
	if err != nil {
		return nil, err
	}

	return append(leftHalf, rightHalf...), nil
}

// ANSI X9.24-1:2009 A.3
//
//	ik is 16 bytes initial key
//	ksn is 10 bytes key serial number
func DeriveCurrentTransactionKey(ik, ksn []byte) ([]byte, error) {
	keyBytes := make([]byte, KeyLen)
	copy(keyBytes, ik)
	ksnBytes := make([]byte, KeySerialLen)
	serializedKsn := serializeKeySerialNumber(ksn)
	copy(ksnBytes, serializedKsn)

	removeTransactionCounter(ksnBytes)

	for shiftBit := TCBits; shiftBit > 0; shiftBit-- {
		var shiftRegVal byte
		shiftReg := make([]byte, 3)

		shiftRegIdx := (shiftBit - 1) >> 3
		shiftRegVal = 0x1 << ((shiftBit - 1) & 0x7)
		shiftReg[shiftRegIdx] = shiftRegVal

		var flag bool
		for i := 0; i < 3; i++ {
			_flag := (shiftReg[i] & serializedKsn[KeySerialLen-1-i]) > 0
			if i == 0 {
				flag = !_flag
			} else {
				flag = flag && !_flag
			}
		}

		if flag {
			// Skip this shift bit
			continue
		}

		// Set shift bit in KSN register
		for i := 0; i < 3; i++ {
			ksnBytes[KeySerialLen-1-i] |= shiftReg[i]
		}

		if nextKey, err := makeNonReversibleKey(ksnBytes, keyBytes); err != nil {
			return nil, err
		} else {
			copy(keyBytes, nextKey)
		}
	}

	transactionKey := make([]byte, KeyLen)
	copy(transactionKey, keyBytes)

	return transactionKey, nil
}

func EncryptPin(currentKey, pin, pan []byte, format string) ([]byte, error) {
	formatter, err := formats.NewFormatter(strings.ToUpper(format))
	if err != nil {
		return nil, err
	}

	blockstr, err := formatter.Encode(string(pin), string(pan))
	if err != nil {
		return nil, err
	}

	return encryptPinblock(currentKey, lib.HexEncode([]byte(blockstr)))
}

func DecryptPin(currentKey, ciphertext, pan []byte, format string) ([]byte, error) {
	formatter, err := formats.NewFormatter(strings.ToUpper(format))
	if err != nil {
		return nil, err
	}

	pinBlock, err := decryptPinblock(currentKey, ciphertext)
	if err != nil {
		return nil, err
	}

	pinstr, err := formatter.Decode(string(lib.HexDecode(pinBlock)), string(pan))
	if err != nil {
		return nil, err
	}

	return lib.HexEncode([]byte(pinstr)), nil
}

func EncryptData(currentKey, plaintext, iv []byte, action string) ([]byte, error) {
	dataKey := make([]byte, KeyLen)
	copy(dataKey, currentKey)

	if action != ActionRequest && action != ActionResponse {
		action = ActionDefault
	}

	// ANSI X9.24-1:2009 A.4.1, table A-1
	if action == ActionRequest {
		dataKey[5] ^= 0xFF
		dataKey[13] ^= 0xFF
	} else {
		dataKey[3] ^= 0xFF
		dataKey[11] ^= 0xFF
	}

	keyCipher, _ := encryption.NewTripleDesECB(dataKey)
	leftKey, err := keyCipher.Encrypt(dataKey[:DesBlockLen])
	if err != nil {
		return nil, err
	}

	rightKey, err := keyCipher.Encrypt(dataKey[DesBlockLen:])
	if err != nil {
		return nil, err
	}

	newKey := append(leftKey, rightKey...)
	dataCipher, _ := encryption.NewTripleDesECB(newKey)

	repeatCnt := len(plaintext) / DesBlockLen
	if len(plaintext)%DesBlockLen > 0 {
		repeatCnt++
	}
	serializePlaintext := make([]byte, repeatCnt*DesBlockLen)
	copy(serializePlaintext, plaintext)

	ciphertext := make([]byte, len(serializePlaintext))
	// A.4.1 Variants of the Current Key
	// 	Encryption of the data should use T-DEA in CBC mode.
	if iv == nil {
		// default null
		iv = make([]byte, DesBlockLen)
	}
	mode := cipher.NewCBCEncrypter(dataCipher.GetBlock(), iv)
	mode.CryptBlocks(ciphertext, serializePlaintext)

	return ciphertext, nil
}

func DecryptData(currentKey, ciphertext, iv []byte, action string) ([]byte, error) {
	dataKey := make([]byte, KeyLen)
	copy(dataKey, currentKey)

	if action != ActionRequest && action != ActionResponse {
		action = ActionDefault
	}

	// ANSI X9.24-1:2009 A.4.1, table A-1
	if action == ActionRequest {
		dataKey[5] ^= 0xFF
		dataKey[13] ^= 0xFF
	} else {
		dataKey[3] ^= 0xFF
		dataKey[11] ^= 0xFF
	}

	keyCipher, _ := encryption.NewTripleDesECB(dataKey)
	leftKey, err := keyCipher.Encrypt(dataKey[:DesBlockLen])
	if err != nil {
		return nil, err
	}

	rightKey, err := keyCipher.Encrypt(dataKey[DesBlockLen:])
	if err != nil {
		return nil, err
	}

	newKey := append(leftKey, rightKey...)
	dataCipher, _ := encryption.NewTripleDesECB(newKey)

	repeatCnt := len(ciphertext) / DesBlockLen
	if len(ciphertext)%DesBlockLen > 0 {
		repeatCnt++
	}
	serializePlaintext := make([]byte, repeatCnt*DesBlockLen)
	copy(serializePlaintext, ciphertext)

	plaintext := make([]byte, len(serializePlaintext))
	// A.4.1 Variants of the Current Key
	// 	Encryption of the data should use T-DEA in CBC mode.
	if iv == nil {
		// default null
		iv = make([]byte, DesBlockLen)
	}
	mode := cipher.NewCBCDecrypter(dataCipher.GetBlock(), iv)
	mode.CryptBlocks(plaintext, serializePlaintext)

	return plaintext, nil
}

// A.4 DUKPT Test Data Examples
//
//	The MAC operations follow the CBC procedure described in ISO 16609 section C.4 using padding
//	method 1 defined in ISO 9797 section 6.1.1. Here is an explanation of the steps:
func GenerateMac(currentKey, plaintext []byte, action string) ([]byte, error) {
	dataKey := make([]byte, KeyLen)
	copy(dataKey, currentKey)

	if action != ActionRequest && action != ActionResponse {
		action = ActionDefault
	}

	// ANSI X9.24-1:2009 A.4.1, table A-1
	if action == ActionRequest {
		dataKey[6] ^= 0xFF
		dataKey[14] ^= 0xFF
	} else {
		dataKey[4] ^= 0xFF
		dataKey[12] ^= 0xFF
	}

	leftKey := dataKey[:DesBlockLen]
	rightKey := dataKey[DesBlockLen:]

	repeatCnt := len(plaintext) / DesBlockLen
	if len(plaintext)%DesBlockLen > 0 {
		repeatCnt++
	}
	serializePlaintext := make([]byte, repeatCnt*DesBlockLen)
	copy(serializePlaintext, plaintext)

	var err error
	initialVector := make([]byte, DesBlockLen)
	leftCipher, _ := encryption.NewDesECB(leftKey)
	for partNum := 0; partNum < repeatCnt; partNum++ {
		macPart := plaintext[partNum*DesBlockLen : (partNum+1)*DesBlockLen]
		for in, _ := range initialVector {
			initialVector[in] = initialVector[in] ^ macPart[in]
		}
		initialVector, err = leftCipher.Encrypt(initialVector)
		if err != nil {
			return nil, err
		}
	}

	var ciphertext []byte
	rightCipher, _ := encryption.NewDesECB(rightKey)
	// Decrypt the result from step (e) with the right half of the MAC Encryption Key
	ciphertext, err = rightCipher.Decrypt(initialVector)
	if err != nil {
		return nil, err
	}

	// Encrypt the result from step (g) with the left half of the MAC Encryption Key
	ciphertext, err = leftCipher.Encrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}
