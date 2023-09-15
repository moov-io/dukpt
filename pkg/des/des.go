package des

/*
ANS X9.24-1:2009 (Retail Financial Services Symmetric Key Management)
*/

import (
	"crypto/cipher"
	"fmt"
	"strings"

	"github.com/moov-io/dukpt/encryption"
	"github.com/moov-io/dukpt/pkg"
	"github.com/moov-io/pinblock/formats"
)

// Derive Initial Key (IK) from Base Derivative Key and Key Serial Number
//
// NOTE:
//   - ANSI X9.24-1:2009 A.6 Derivation of the Initial Key
//
// Params:
//   - ksn is 10 bytes key serial number
//   - bdk is 16 bytes base derivative Key
//
// Return Params:
//   - reulst is 16 bytes initial key
//   - err
func DerivationOfInitialKey(bdk, ksn []byte) ([]byte, error) {
	if len(bdk) != keyLen {
		return nil, fmt.Errorf("base derivative key length must be %d bytes", keyLen)
	}

	ksnBytes := serializeKeySerialNumber(ksn)
	removeTransactionCounter(ksnBytes)

	leftCipher, _ := encryption.NewTripleDesECB(bdk)
	leftHalf, err := leftCipher.Encrypt(ksnBytes[:keyLen/2])
	if err != nil {
		return nil, err
	}

	bdkVariant := make([]byte, len(bdk))
	copy(bdkVariant, bdk)
	serializeKeyWithHexadecimal(bdkVariant)

	rightCipher, _ := encryption.NewTripleDesECB(bdkVariant)
	rightHalf, err := rightCipher.Encrypt(ksnBytes[:keyLen/2])
	if err != nil {
		return nil, err
	}

	return append(leftHalf, rightHalf...), nil
}

// Derive DUKPT transaction key (current transaction key) from Initial Key and Key Serial Number
//
//	NOTE:
//	 - ANSI X9.24-1:2009 A.3
//
// Params:
//   - ik is 16 bytes initial key
//   - ksn is 10 bytes key serial number
//
// Return Params:
//   - result is 16 bytes transaction key
//   - err
func DeriveCurrentTransactionKey(ik, ksn []byte) ([]byte, error) {
	keyBytes := make([]byte, keyLen)
	copy(keyBytes, ik)
	ksnBytes := make([]byte, keySerialLen)
	serializedKsn := serializeKeySerialNumber(ksn)
	copy(ksnBytes, serializedKsn)

	removeTransactionCounter(ksnBytes)

	for shiftBit := tcBits; shiftBit > 0; shiftBit-- {
		var shiftRegVal byte
		shiftReg := make([]byte, 3)

		shiftRegIdx := (shiftBit - 1) >> 3
		shiftRegVal = 0x1 << ((shiftBit - 1) & 0x7)
		shiftReg[shiftRegIdx] = shiftRegVal

		var flag bool
		for i := 0; i < 3; i++ {
			_flag := (shiftReg[i] & serializedKsn[keySerialLen-1-i]) > 0
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
			ksnBytes[keySerialLen-1-i] |= shiftReg[i]
		}

		if nextKey, err := makeNonReversibleKey(ksnBytes, keyBytes); err != nil {
			return nil, err
		} else {
			copy(keyBytes, nextKey)
		}
	}

	transactionKey := make([]byte, keyLen)
	copy(transactionKey, keyBytes)

	return transactionKey, nil
}

// Encrypt PIN block using DUKPT transaction key
//
// NOTE:
//   - ANSI X9.24-1:2009 A.4.1 Variants of the Current Key
//   - ANSI X9.24-1:2009 A.2 Processing Algorithms ("Request PIN Entry 2")
//
// Params:
//   - current key is 16 bytes transaction key
//   - pin is not formatted pin string
//   - pan is not formatted pan string
//   - format is pinblock format
//     ("ISO-0", "ISO-1", "ISO-2", "ISO-3", "ISO-4", "ANSI", "ECI1", "ECI2", "ECI3", "ECI4", "VISA1", "VISA2", "VISA3", "VISA4")
//
// Return Params:
//   - result is cipher text
//   - err
func EncryptPin(currentKey []byte, pin, pan string, format string) ([]byte, error) {
	formatter, err := formats.NewFormatter(strings.ToUpper(format))
	if err != nil {
		return nil, err
	}

	blockstr, err := formatter.Encode(pin, pan)
	if err != nil {
		return nil, err
	}

	return encryptPinblock(currentKey, pkg.HexDecode(blockstr))
}

// Decrypt PIN block using DUKPT transaction key
//
// NOTE:
//   - A.4.1 Variants of the Current Key
//   - A.2 Processing Algorithms ("Request PIN Entry 2")
//
// Params:
//   - current key is 16 bytes transaction key
//   - cipher text is encrypted text transformed from plaintext using an encryption algorithm
//   - pan is not formatted pan string
//   - format is pinblock format
//     ("ISO-0", "ISO-1", "ISO-2", "ISO-3", "ISO-4", "ANSI", "ECI1", "ECI2", "ECI3", "ECI4", "VISA1", "VISA2", "VISA3", "VISA4")
//
// Return Params:
//   - result is pin string (plain text)
//   - err
func DecryptPin(currentKey, ciphertext []byte, pan string, format string) (string, error) {
	formatter, err := formats.NewFormatter(strings.ToUpper(format))
	if err != nil {
		return "", err
	}

	pinBlock, err := decryptPinblock(currentKey, ciphertext)
	if err != nil {
		return "", err
	}

	pinstr, err := formatter.Decode(pkg.HexEncode(pinBlock), pan)
	if err != nil {
		return "", err
	}

	return pinstr, nil
}

// Generate MAC using DUKPT transaction key
//
// NOTE:
//   - ANSI X9.24-1:2009 A.4.1 Variants of the Current Key
//   - ANSI X9.24-1:2009 A.4 DUKPT Test Data Examples (CBC procedure described in ISO 16609 section C.4)
//
// Params:
//   - current key is 16 bytes transaction key
//   - plain text is transaction request data
//   - action is request or response action
//
// Return Params:
//   - result is generated mac (use the first 4 bytes of this result)
//   - err
func GenerateMac(currentKey []byte, plainText, action string) ([]byte, error) {
	dataKey := make([]byte, keyLen)
	copy(dataKey, currentKey)

	if action != pkg.ActionRequest && action != pkg.ActionResponse {
		action = pkg.ActionRequest
	}

	// ANSI X9.24-1:2009 A.4.1, table A-1
	if action == pkg.ActionRequest {
		dataKey[6] ^= 0xFF
		dataKey[14] ^= 0xFF
	} else {
		dataKey[4] ^= 0xFF
		dataKey[12] ^= 0xFF
	}

	leftKey := dataKey[:desBlockLen]
	rightKey := dataKey[desBlockLen:]

	plainTextBytes := []byte(plainText)
	repeatCnt := len(plainTextBytes) / desBlockLen
	if len(plainTextBytes)%desBlockLen > 0 {
		repeatCnt++
	}
	serializePlaintext := make([]byte, repeatCnt*desBlockLen)
	copy(serializePlaintext, plainTextBytes)

	var err error
	initialVector := make([]byte, desBlockLen)
	leftCipher, _ := encryption.NewDesECB(leftKey)
	for partNum := 0; partNum < repeatCnt; partNum++ {
		macPart := plainTextBytes[partNum*desBlockLen : (partNum+1)*desBlockLen]
		for in := range initialVector {
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

// Encrypt Data using DUKPT transaction key
//
// NOTE:
//   - ANSI X9.24-1:2009 A.4.1 Variants of the Current Key
//   - ANSI X9.24-1:2009 A.4.1, figure A-2
//   - Encryption of the data should use T-DEA in CBC mode.
//
// Params:
//   - current key is 16 bytes transaction key
//   - iv is initial vector
//   - plain text is transaction request data
//   - action is request or response action
//
// Return Params:
//   - result is encrypted data
//   - err
func EncryptData(currentKey, iv []byte, plainText, action string) ([]byte, error) {
	dataKey := make([]byte, keyLen)
	copy(dataKey, currentKey)

	if action != pkg.ActionRequest && action != pkg.ActionResponse {
		action = pkg.ActionRequest
	}

	// ANSI X9.24-1:2009 A.4.1, table A-1
	if action == pkg.ActionRequest {
		dataKey[5] ^= 0xFF
		dataKey[13] ^= 0xFF
	} else {
		dataKey[3] ^= 0xFF
		dataKey[11] ^= 0xFF
	}

	keyCipher, _ := encryption.NewTripleDesECB(dataKey)
	leftKey, err := keyCipher.Encrypt(dataKey[:desBlockLen])
	if err != nil {
		return nil, err
	}

	rightKey, err := keyCipher.Encrypt(dataKey[desBlockLen:])
	if err != nil {
		return nil, err
	}

	newKey := append(leftKey, rightKey...)
	dataCipher, _ := encryption.NewTripleDesECB(newKey)

	plainTextBytes := []byte(plainText)
	repeatCnt := len(plainTextBytes) / desBlockLen
	if len(plainTextBytes)%desBlockLen > 0 {
		repeatCnt++
	}
	serializePlaintext := make([]byte, repeatCnt*desBlockLen)
	copy(serializePlaintext, plainTextBytes)

	ciphertext := make([]byte, len(serializePlaintext))
	// A.4.1 Variants of the Current Key
	// 	Encryption of the data should use T-DEA in CBC mode.
	if iv == nil {
		// default null
		iv = make([]byte, desBlockLen)
	}
	if len(iv) < desBlockLen {
		iv = append(iv, make([]byte, desBlockLen-len(iv))...)
	}

	mode := cipher.NewCBCEncrypter(dataCipher.GetBlock(), iv)
	mode.CryptBlocks(ciphertext, serializePlaintext)

	return ciphertext, nil
}

// Decrypt Data using DUKPT transaction key
//
// NOTE:
//   - ANSI X9.24-1:2009 A.4.1 Variants of the Current Key
//   - ANSI X9.24-1:2009 A.4.1 figure A-2
//   - Encryption of the data should use T-DEA in CBC mode.
//
// Params:
//   - current key is 16 bytes transaction key
//   - cipher text is encrypted text
//   - iv is initial vector
//   - action is request or response action
//
// Return Params:
//   - result is transaction request data ( must be a multiple of tdes block length [8])
//   - err
func DecryptData(currentKey, ciphertext, iv []byte, action string) (string, error) {
	dataKey := make([]byte, keyLen)
	copy(dataKey, currentKey)

	if action != pkg.ActionRequest && action != pkg.ActionResponse {
		action = pkg.ActionRequest
	}

	// ANSI X9.24-1:2009 A.4.1, table A-1
	if action == pkg.ActionRequest {
		dataKey[5] ^= 0xFF
		dataKey[13] ^= 0xFF
	} else {
		dataKey[3] ^= 0xFF
		dataKey[11] ^= 0xFF
	}

	keyCipher, _ := encryption.NewTripleDesECB(dataKey)
	leftKey, err := keyCipher.Encrypt(dataKey[:desBlockLen])
	if err != nil {
		return "", err
	}

	rightKey, err := keyCipher.Encrypt(dataKey[desBlockLen:])
	if err != nil {
		return "", err
	}

	newKey := append(leftKey, rightKey...)
	dataCipher, _ := encryption.NewTripleDesECB(newKey)

	repeatCnt := len(ciphertext) / desBlockLen
	if len(ciphertext)%desBlockLen > 0 {
		repeatCnt++
	}
	serializePlaintext := make([]byte, repeatCnt*desBlockLen)
	copy(serializePlaintext, ciphertext)

	plaintext := make([]byte, len(serializePlaintext))
	// A.4.1 Variants of the Current Key
	// 	Encryption of the data should use T-DEA in CBC mode.
	if iv == nil {
		// default null
		iv = make([]byte, desBlockLen)
	}

	if len(iv) > desBlockLen {
		iv = iv[:desBlockLen]
	}
	
	mode := cipher.NewCBCDecrypter(dataCipher.GetBlock(), iv)
	mode.CryptBlocks(plaintext, serializePlaintext)

	return string(plaintext), nil
}
