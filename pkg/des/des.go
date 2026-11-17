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
//
// The returned Initial Key belongs to the caller, who should clear it with
// dukpt.Clear once it is no longer needed. bdk is not
// modified; the BDK variant and both halves of the Initial Key built along the
// way are cleared before returning.
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
	defer wipe(leftHalf)

	bdkVariant := make([]byte, len(bdk))
	defer wipe(bdkVariant)
	copy(bdkVariant, bdk)
	serializeKeyWithHexadecimal(bdkVariant)

	rightCipher, _ := encryption.NewTripleDesECB(bdkVariant)
	rightHalf, err := rightCipher.Encrypt(ksnBytes[:keyLen/2])
	if err != nil {
		return nil, err
	}
	defer wipe(rightHalf)

	initialKey := make([]byte, 0, keyLen)
	initialKey = append(initialKey, leftHalf...)
	initialKey = append(initialKey, rightHalf...)
	return initialKey, nil
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
//
// The returned transaction key belongs to the caller, who should clear it with
// dukpt.Clear once it is no longer needed. ik is not modified. The Key Register and every
// intermediate key are cleared before returning, including on an error.
func DeriveCurrentTransactionKey(ik, ksn []byte) ([]byte, error) {
	keyBytes := make([]byte, keyLen)
	defer wipe(keyBytes)
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

		nextKey, err := makeNonReversibleKey(ksnBytes, keyBytes)
		if err != nil {
			return nil, err
		}
		copy(keyBytes, nextKey)
		wipe(nextKey)
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
//
// The PIN encryption key variant and the clear PIN block are cleared before
// returning; currentKey is not modified and stays the caller's to clear. pin
// and pan are strings, and github.com/moov-io/pinblock formats the PIN block as
// a hex string, so copies of the PIN remain in memory until the garbage
// collector reuses it.
func EncryptPin(currentKey []byte, pin, pan string, format string) ([]byte, error) {
	formatter, err := formats.NewFormatter(strings.ToUpper(format))
	if err != nil {
		return nil, err
	}

	blockstr, err := formatter.Encode(pin, pan)
	if err != nil {
		return nil, err
	}

	pinBlock := pkg.HexDecode(blockstr)
	defer wipe(pinBlock)
	return encryptPinblock(currentKey, pinBlock)
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
//
// The PIN encryption key variant and the clear PIN block are cleared before
// returning; currentKey is not modified and stays the caller's to clear. The
// PIN block is decoded through a hex string and the PIN is returned as a
// string, neither of which can be cleared.
func DecryptPin(currentKey, ciphertext []byte, pan string, format string) (string, error) {
	formatter, err := formats.NewFormatter(strings.ToUpper(format))
	if err != nil {
		return "", err
	}

	pinBlock, err := decryptPinblock(currentKey, ciphertext)
	if err != nil {
		return "", err
	}
	defer wipe(pinBlock)

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
//
// The MAC key variant and the zero-padded copy of plainText are cleared before
// returning; currentKey is not modified and stays the caller's to clear.
// plainText is a string, which cannot be cleared.
func GenerateMac(currentKey []byte, plainText, action string) ([]byte, error) {
	dataKey := make([]byte, keyLen)
	defer wipe(dataKey)
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

	repeatCnt := len(plainText) / desBlockLen
	if len(plainText)%desBlockLen > 0 {
		repeatCnt++
	}
	serializePlaintext := make([]byte, repeatCnt*desBlockLen)
	defer wipe(serializePlaintext)
	copy(serializePlaintext, plainText)

	var err error
	initialVector := make([]byte, desBlockLen)
	leftCipher, _ := encryption.NewDesECB(leftKey)
	for partNum := 0; partNum < repeatCnt; partNum++ {
		macPart := serializePlaintext[partNum*desBlockLen : (partNum+1)*desBlockLen]
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
//   - plain text is the data to encrypt, zero-padded to a multiple of 8 bytes
//   - action is request or response action
//
// Return Params:
//   - result is encrypted data
//   - err
//
// The data key variant, the derived data encryption key and its halves, and
// the padded copy of plainText are cleared before returning; currentKey is not
// modified and stays the caller's to clear. plainText is a string, which cannot
// be cleared.
func EncryptData(currentKey, iv []byte, plainText, action string) ([]byte, error) {
	dataKey := make([]byte, keyLen)
	defer wipe(dataKey)
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
	defer wipe(leftKey)

	rightKey, err := keyCipher.Encrypt(dataKey[desBlockLen:])
	if err != nil {
		return nil, err
	}
	defer wipe(rightKey)

	newKey := make([]byte, 0, keyLen)
	newKey = append(newKey, leftKey...)
	newKey = append(newKey, rightKey...)
	defer wipe(newKey)
	dataCipher, _ := encryption.NewTripleDesECB(newKey)

	repeatCnt := len(plainText) / desBlockLen
	if len(plainText)%desBlockLen > 0 {
		repeatCnt++
	}
	serializePlaintext := make([]byte, repeatCnt*desBlockLen)
	defer wipe(serializePlaintext)
	copy(serializePlaintext, plainText)

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

	// codeql[go/weak-cryptographic-algorithm] TDEA/CBC required by ANSI X9.24-1 DUKPT
	mode := cipher.NewCBCEncrypter(dataCipher.GetBlock(), iv)
	// codeql[go/weak-cryptographic-algorithm] TDEA/CBC required by ANSI X9.24-1 DUKPT
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
//   - result is the decrypted data, a multiple of the TDEA block length (8
//     bytes); it includes any padding added before encryption
//   - err
//
// The data key variant, the derived data encryption key and its halves, and
// the buffer the data is decrypted into are cleared before returning;
// currentKey is not modified and stays the caller's to clear. The result is a
// string, which the caller cannot clear: the decrypted data stays in memory
// until the garbage collector reuses it.
func DecryptData(currentKey, ciphertext, iv []byte, action string) (string, error) {
	dataKey := make([]byte, keyLen)
	defer wipe(dataKey)
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
	defer wipe(leftKey)

	rightKey, err := keyCipher.Encrypt(dataKey[desBlockLen:])
	if err != nil {
		return "", err
	}
	defer wipe(rightKey)

	newKey := make([]byte, 0, keyLen)
	newKey = append(newKey, leftKey...)
	newKey = append(newKey, rightKey...)
	defer wipe(newKey)
	dataCipher, _ := encryption.NewTripleDesECB(newKey)

	repeatCnt := len(ciphertext) / desBlockLen
	if len(ciphertext)%desBlockLen > 0 {
		repeatCnt++
	}
	serializePlaintext := make([]byte, repeatCnt*desBlockLen)
	copy(serializePlaintext, ciphertext)

	plaintext := make([]byte, len(serializePlaintext))
	defer wipe(plaintext)
	// A.4.1 Variants of the Current Key
	// 	Encryption of the data should use T-DEA in CBC mode.
	if iv == nil {
		// default null
		iv = make([]byte, desBlockLen)
	}

	if len(iv) > desBlockLen {
		iv = iv[:desBlockLen]
	}

	// codeql[go/weak-cryptographic-algorithm] TDEA/CBC required by ANSI X9.24-1 DUKPT
	mode := cipher.NewCBCDecrypter(dataCipher.GetBlock(), iv)
	// codeql[go/weak-cryptographic-algorithm] TDEA/CBC required by ANSI X9.24-1 DUKPT
	mode.CryptBlocks(plaintext, serializePlaintext)

	return string(plaintext), nil
}
