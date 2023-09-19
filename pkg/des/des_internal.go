package des

import (
	"bytes"
	"crypto/des" //nolint:gosec
	"fmt"
	"github.com/moov-io/dukpt/encryption"
)

const (
	keyLen       = 16
	keySerialLen = 10
	tcBits       = 21
	desBlockLen  = 8
)

func serializeKeySerialNumber(ksn []byte) []byte {
	var ksnBytes []byte

	// If the key serial number is less than 10 bytes, pad to the left with hex "FF" bytes
	if len(ksn) < keySerialLen {
		ksnBytes = append(bytes.Repeat([]byte{0xFF}, keySerialLen-len(ksn)), ksn...)
	} else {
		ksnBytes = make([]byte, keySerialLen)
		copy(ksnBytes, ksn)
	}

	return ksnBytes
}

// Extract transaction counter value from KSN. The transaction counter is the last 21 bits of the KSN.
func removeTransactionCounter(ksn []byte) {
	if len(ksn) != keySerialLen {
		return
	}

	// Set the 21 least-significant bits of this 10-byte register to zero.
	ksn[7] &= 0xE0
	ksn[8] = 0
	ksn[9] = 0
}

func serializeKeyWithHexadecimal(key []byte) {
	if len(key) != keyLen {
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

// Non-reversible Key Generation Process
func makeNonReversibleKey(ksnBytes, keyBytes []byte) ([]byte, error) {
	var err error
	cryptoReg1 := make([]byte, des.BlockSize)
	cryptoReg2 := make([]byte, des.BlockSize)

	// The 64 right-most bits of the Key Serial Number Register is transferred into Crypto Register-1
	copy(cryptoReg1, ksnBytes[len(ksnBytes)-des.BlockSize:])

	// 1) Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-2
	for index := range cryptoReg2 {
		cryptoReg2[index] = cryptoReg1[index] ^ keyBytes[index+8]
	}

	// 2) Crypto Register-2 DEA-encrypted using, as the key, the left half of the Key Register goes to Crypto Register-2
	cipher1, _ := encryption.NewDesECB(keyBytes[:des.BlockSize])
	cryptoReg2, err = cipher1.Encrypt(cryptoReg2)
	if err != nil {
		return nil, err
	}

	// 3) Crypto Register-2 XORed with the right half of the Key Register goes to Crypto Register-2
	for index := range cryptoReg2 {
		cryptoReg2[index] = cryptoReg2[index] ^ keyBytes[index+8]
	}

	// See https://github.com/Abirdcfly/dupword/issues/26 for a fix to needing nolint
	//nolint:dupword
	// 4) XOR the Key Register with hexadecimal C0C0 C0C0 0000 0000 C0C0 C0C0 0000 0000
	serializeKeyWithHexadecimal(keyBytes)

	// 5) Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-1
	for index := range cryptoReg1 {
		cryptoReg1[index] = cryptoReg1[index] ^ keyBytes[index+keyLen/2]
	}

	// 6) Crypto Register-1 DEA-encrypted using, as the key, the left half of the Key Register goes to Crypto Register-1
	cipher2, _ := encryption.NewDesECB(keyBytes[:des.BlockSize])
	cryptoReg1, err = cipher2.Encrypt(cryptoReg1)
	if err != nil {
		return nil, err
	}

	// 7) Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-1
	for index := range cryptoReg1 {
		cryptoReg1[index] = cryptoReg1[index] ^ keyBytes[index+keyLen/2]
	}

	return append(cryptoReg1, cryptoReg2...), nil
}

func encryptPinblock(currentKey, pinblock []byte) ([]byte, error) {
	if len(currentKey) != keyLen {
		return nil, fmt.Errorf("current key length must be %d bytes", keyLen)
	}

	pinKey := make([]byte, keyLen)
	copy(pinKey, currentKey)

	// ANSI X9.24-1:2009 A.4.1, table A-1
	pinKey[7] ^= 0xFF
	pinKey[15] ^= 0xFF

	cipher, _ := encryption.NewTripleDesECB(pinKey)

	return cipher.Encrypt(pinblock)
}

func decryptPinblock(currentKey, ciphertext []byte) ([]byte, error) {
	if len(currentKey) != keyLen {
		return nil, fmt.Errorf("current key length must be %d bytes", keyLen)
	}

	pinKey := make([]byte, keyLen)
	copy(pinKey, currentKey)

	// ANSI X9.24-1:2009 A.4.1, table A-1
	pinKey[7] ^= 0xFF
	pinKey[15] ^= 0xFF

	cipher, _ := encryption.NewTripleDesECB(pinKey)

	return cipher.Decrypt(ciphertext)
}
