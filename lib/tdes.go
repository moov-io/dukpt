package lib

import (
	"bytes"
	"crypto/des"
	"fmt"
	"math/big"

	"github.com/moov-io/dukpt/encryption"
	blocker "github.com/moov-io/pinblock/formats"
)

const (
	KeyLen                = 16
	KeySerialLen          = 10
	TCBits                = 21
	DukptTdesTcMax        = 0x1FF800
	DukptTdesPinblockLen  = 8
	DukptTdesMacLen       = 4
	DukptTdesBlockLen     = 8
	DukptLibVersionString = ""

	PinblookISO0 = "ISO-0"
	PinblookISO1 = "ISO-1"
	PinblookISO2 = "ISO-2"
	PinblookISO3 = "ISO-3"
	PinblookISO4 = "ISO-4"
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

	leftCipher, _ := encryption.NewTDesECB(bdk)
	leftHalf, err := leftCipher.Encrypt(ksnBytes[:KeyLen/2])
	if err != nil {
		return nil, err
	}

	bdkVariant := make([]byte, len(bdk))
	copy(bdkVariant, bdk)
	serializeKeyWithHexadecimal(bdkVariant)

	rightCipher, _ := encryption.NewTDesECB(bdkVariant)
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
	var pinblock []byte
	var formater blocker.FormatA

	switch format {
	case PinblookISO0:
		formater = blocker.NewISO0()
	}

	return nil, nil
}

// internal functions

func serializeKeySerialNumber(ksn []byte) []byte {
	var ksnBytes []byte

	// If the key serial number is less than 10 bytes, pad to the left with hex "FF" bytes
	if len(ksn) < KeySerialLen {
		ksnBytes = append(bytes.Repeat([]byte{0xFF}, KeySerialLen-len(ksn)), ksn...)
	} else {
		ksnBytes = make([]byte, KeySerialLen)
		copy(ksnBytes, ksn)
	}

	return ksnBytes
}

// Extract transaction counter value from KSN. The transaction counter is the last 21 bits of the KSN.
func removeTransactionCounter(ksn []byte) {
	if len(ksn) != KeySerialLen {
		return
	}

	// Set the 21 least-significant bits of this 10-byte register to zero.
	ksn[7] &= 0xE0
	ksn[8] = 0
	ksn[9] = 0
}

func serializeKeyWithHexadecimal(key []byte) {
	if len(key) != KeyLen {
		return
	}

	key[0] ^= 0xC0
	key[1] ^= 0xC0
	key[2] ^= 0xC0
	key[3] ^= 0xC0
	key[8] ^= 0xC0
	key[9] ^= 0xC0
	key[10] ^= 0xC0
	key[11] ^= 0xC0
}

// Extract transaction counter value from KSN. The transaction counter is the last 21 bits of the KSN.
func getTransactionCounter(ksn []byte) (int64, error) {
	if len(ksn) != KeySerialLen {
		return 0, fmt.Errorf("invalid key length")
	}

	lastBytes := ksn[KeyLen-3:]
	lastBytes[0] = lastBytes[0] & 0x1f
	return int64(big.NewInt(0).SetBytes(lastBytes).Uint64()), nil
}

func isValidTransactionCounter(ksn []byte) bool {
	tc, err := getTransactionCounter(ksn)
	if err != nil {
		return false
	}

	bitCount := 0
	for v := tc; v != 0; bitCount++ {
		v &= v - 1
	}

	// Transaction counter should have 10 or fewer "one" bits
	if bitCount > 10 {
		return false
	}

	return true
}

// A.2 Processing Algorithms, “Non-reversible Key Generation Process” (Local Subroutine)
func makeNonReversibleKey(ksnBytes, keyBytes []byte) ([]byte, error) {
	var err error
	cryptoReg1 := make([]byte, des.BlockSize)
	cryptoReg2 := make([]byte, des.BlockSize)

	// The 64 right-most bits of the Key Serial Number Register is transferred into Crypto Register-1
	copy(cryptoReg1, ksnBytes[len(ksnBytes)-des.BlockSize:])

	// 1) Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-2
	for index, _ := range cryptoReg2 {
		cryptoReg2[index] = cryptoReg1[index] ^ keyBytes[index+8]
	}

	// 2) Crypto Register-2 DEA-encrypted using, as the key, the left half of the Key Register goes to Crypto Register-2
	cipher1, _ := encryption.NewDesECB(keyBytes[:des.BlockSize])
	cryptoReg2, err = cipher1.Encrypt(cryptoReg2)
	if err != nil {
		return nil, err
	}

	// 3) Crypto Register-2 XORed with the right half of the Key Register goes to Crypto Register-2
	for index, _ := range cryptoReg2 {
		cryptoReg2[index] = cryptoReg2[index] ^ keyBytes[index+8]
	}

	// 4) XOR the Key Register with hexadecimal C0C0 C0C0 0000 0000 C0C0 C0C0 0000 0000
	serializeKeyWithHexadecimal(keyBytes)

	// 5) Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-1
	for index, _ := range cryptoReg1 {
		cryptoReg1[index] = cryptoReg1[index] ^ keyBytes[index+KeyLen/2]
	}

	// 6) Crypto Register-1 DEA-encrypted using, as the key, the left half of the Key Register goes to Crypto Register-1
	cipher2, _ := encryption.NewDesECB(keyBytes[:des.BlockSize])
	cryptoReg1, err = cipher2.Encrypt(cryptoReg1)
	if err != nil {
		return nil, err
	}

	// 7) Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-1
	for index, _ := range cryptoReg1 {
		cryptoReg1[index] = cryptoReg1[index] ^ keyBytes[index+KeyLen/2]
	}

	return append(cryptoReg1, cryptoReg2...), nil
}

func encryptPinblock(currentKey, pinblock []byte) ([]byte, error) {
	if len(currentKey) != KeyLen {
		return nil, fmt.Errorf("current key length must be %d bytes", KeyLen)
	}

	pinKey := make([]byte, KeyLen)
	copy(pinKey, currentKey)

	// ANSI X9.24-1:2009 A.4.1, table A-1
	pinKey[7] ^= 0xFF
	pinKey[15] ^= 0xFF

	cipher, _ := encryption.NewTDesECB(pinKey)

	return cipher.Encrypt(pinblock)
}

func decryptPinblock(currentKey, ciphertext []byte) ([]byte, error) {
	if len(currentKey) != KeyLen {
		return nil, fmt.Errorf("current key length must be %d bytes", KeyLen)
	}

	pinKey := make([]byte, KeyLen)
	copy(pinKey, currentKey)

	// ANSI X9.24-1:2009 A.4.1, table A-1
	pinKey[7] ^= 0xFF
	pinKey[15] ^= 0xFF

	cipher, _ := encryption.NewTDesECB(pinKey)

	return cipher.Decrypt(ciphertext)
}
