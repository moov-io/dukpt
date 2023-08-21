package lib

import (
	"fmt"
	
	"github.com/moov-io/dukpt/encryption"
)

const (
	KeyLen         = 16
	KeySerialLen   = 10
	TCBits         = 21
	DesTcMax       = 0x1FF800
	DesPinblockLen = 8
	DesMacLen      = 4
	DesBlockLen    = 8

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
	/*
		var pinblock []byte
		var formater blocker.FormatA

		switch format {
		case PinblookISO0:
			formater = blocker.NewISO0()
		}
	*/

	return nil, nil
}
