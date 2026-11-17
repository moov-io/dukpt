package des

import (
	"bytes"
	"crypto/des" //nolint:gosec
	"fmt"

	"github.com/moov-io/dukpt/encryption"
	"github.com/moov-io/dukpt/internal/memzero"
)

// wipe clears a buffer that held key material, a clear PIN block, or data
// decrypted with a key. It is a variable only so tests can observe which
// buffers the package clears.
var wipe = memzero.Bytes

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

// Non-reversible Key Generation Process (ANSI X9.24-1:2009 A.2)
//
// keyBytes is the Key Register and is modified in place (step 4). The returned
// key belongs to the caller, who must clear it. Both crypto registers hold
// key-derived values at every step, so each is cleared when replaced and again
// on return, including on an error.
func makeNonReversibleKey(ksnBytes, keyBytes []byte) ([]byte, error) {
	if len(keyBytes) < keyLen {
		return nil, fmt.Errorf("key register length must be at least %d bytes", keyLen)
	}
	if len(ksnBytes) < des.BlockSize {
		return nil, fmt.Errorf("ksn length must be at least %d bytes", des.BlockSize)
	}

	cryptoReg1 := make([]byte, des.BlockSize)
	cryptoReg2 := make([]byte, des.BlockSize)
	// A closure, so it clears whichever buffers the registers hold on return.
	defer func() {
		wipe(cryptoReg1)
		wipe(cryptoReg2)
	}()

	// The 64 right-most bits of the Key Serial Number Register is transferred into Crypto Register-1
	copy(cryptoReg1, ksnBytes[len(ksnBytes)-des.BlockSize:])

	// Split the 16-byte key register so index math stays in bounds for static analysis.
	leftKey := keyBytes[:des.BlockSize]
	rightKey := keyBytes[des.BlockSize:keyLen]

	// 1) Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-2
	for index := range cryptoReg2 {
		cryptoReg2[index] = cryptoReg1[index] ^ rightKey[index]
	}

	// 2) Crypto Register-2 DEA-encrypted using, as the key, the left half of the Key Register goes to Crypto Register-2
	cipher1, _ := encryption.NewDesECB(leftKey)
	encrypted, err := cipher1.Encrypt(cryptoReg2)
	wipe(cryptoReg2)
	if err != nil {
		return nil, err
	}
	cryptoReg2 = encrypted

	// 3) Crypto Register-2 XORed with the right half of the Key Register goes to Crypto Register-2
	for index := range cryptoReg2 {
		cryptoReg2[index] = cryptoReg2[index] ^ rightKey[index]
	}

	// See https://github.com/Abirdcfly/dupword/issues/26 for a fix to needing nolint
	//nolint:dupword
	// 4) XOR the Key Register with hexadecimal C0C0 C0C0 0000 0000 C0C0 C0C0 0000 0000
	serializeKeyWithHexadecimal(keyBytes)
	// Re-slice after the key register XOR (left half may have changed).
	leftKey = keyBytes[:des.BlockSize]
	rightKey = keyBytes[des.BlockSize:keyLen]

	// 5) Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-1
	for index := range cryptoReg1 {
		cryptoReg1[index] = cryptoReg1[index] ^ rightKey[index]
	}

	// 6) Crypto Register-1 DEA-encrypted using, as the key, the left half of the Key Register goes to Crypto Register-1
	cipher2, _ := encryption.NewDesECB(leftKey)
	encrypted, err = cipher2.Encrypt(cryptoReg1)
	wipe(cryptoReg1)
	if err != nil {
		return nil, err
	}
	cryptoReg1 = encrypted

	// 7) Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-1
	for index := range cryptoReg1 {
		cryptoReg1[index] = cryptoReg1[index] ^ rightKey[index]
	}

	// A new 16-byte slice: appending to cryptoReg1 would reallocate it anyway,
	// and the registers are cleared by the deferred wipe.
	nextKey := make([]byte, 0, keyLen)
	nextKey = append(nextKey, cryptoReg1...)
	nextKey = append(nextKey, cryptoReg2...)
	return nextKey, nil
}

func encryptPinblock(currentKey, pinblock []byte) ([]byte, error) {
	if len(currentKey) != keyLen {
		return nil, fmt.Errorf("current key length must be %d bytes", keyLen)
	}

	pinKey := make([]byte, keyLen)
	defer wipe(pinKey)
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
	defer wipe(pinKey)
	copy(pinKey, currentKey)

	// ANSI X9.24-1:2009 A.4.1, table A-1
	pinKey[7] ^= 0xFF
	pinKey[15] ^= 0xFF

	cipher, _ := encryption.NewTripleDesECB(pinKey)

	return cipher.Decrypt(ciphertext)
}
