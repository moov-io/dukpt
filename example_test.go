// Copyright 2020 The Moov Authors
// Use of this source code is governed by an Apache License
// license that can be found in the LICENSE file.

package dukpt_test

import (
	"fmt"
	"log"

	"github.com/moov-io/dukpt"
	"github.com/moov-io/dukpt/pkg"
	"github.com/moov-io/dukpt/pkg/aes"
	"github.com/moov-io/dukpt/pkg/des"
)

// Example_des derives TDES DUKPT keys from the ANSI X9.24-1 test vectors,
// then encrypts and decrypts an ISO-0 PIN block.
func Example_des() {
	bdk := pkg.HexDecode("0123456789ABCDEFFEDCBA9876543210")
	ksn := pkg.HexDecode("FFFF9876543210E00001")

	ik, err := des.DerivationOfInitialKey(bdk, ksn)
	if err != nil {
		log.Fatal(err)
	}
	defer dukpt.Clear(ik)

	transactionKey, err := des.DeriveCurrentTransactionKey(ik, ksn)
	if err != nil {
		log.Fatal(err)
	}
	defer dukpt.Clear(transactionKey)

	encryptedPin, err := des.EncryptPin(transactionKey, "1234", "4012345678909", "ISO-0")
	if err != nil {
		log.Fatal(err)
	}

	decryptedPin, err := des.DecryptPin(transactionKey, encryptedPin, "4012345678909", "ISO-0")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("initial key:    ", pkg.HexEncode(ik))
	fmt.Println("transaction key:", pkg.HexEncode(transactionKey))
	fmt.Println("encrypted PIN:  ", pkg.HexEncode(encryptedPin))
	fmt.Println("decrypted PIN:  ", decryptedPin)
	// Output:
	// initial key:     6ac292faa1315b4d858ab3a3d7d5933a
	// transaction key: 042666b49184cfa368de9628d0397bc9
	// encrypted PIN:   1b9c1845eb993a7a
	// decrypted PIN:   1234
}

// Example_aes derives AES DUKPT keys from the ANSI X9.24-3 test vectors,
// then encrypts and decrypts an ISO-4 PIN block and data.
func Example_aes() {
	bdk := pkg.HexDecode("FEDCBA9876543210F1F1F1F1F1F1F1F1")
	ksn := pkg.HexDecode("123456789012345600000001")

	// Check a KSN you receive before you derive keys from it.
	if !pkg.IsValidAesKsn(ksn) {
		log.Fatal("invalid KSN")
	}

	// For AES, DerivationOfInitialKey uses the first 8 bytes of the KSN
	// (the Initial Key ID).
	ik, err := aes.DerivationOfInitialKey(bdk, ksn)
	if err != nil {
		log.Fatal(err)
	}
	defer dukpt.Clear(ik)

	transactionKey, err := aes.DeriveCurrentTransactionKey(ik, ksn)
	if err != nil {
		log.Fatal(err)
	}
	defer dukpt.Clear(transactionKey)

	encryptedPin, err := aes.EncryptPin(transactionKey, ksn, "1234", "4111111111111111", aes.KeyAES128Type)
	if err != nil {
		log.Fatal(err)
	}
	decryptedPin, err := aes.DecryptPin(transactionKey, ksn, encryptedPin, "4111111111111111", aes.KeyAES128Type)
	if err != nil {
		log.Fatal(err)
	}

	iv := make([]byte, 16)
	encryptedData, err := aes.EncryptData(transactionKey, ksn, iv, "hello", aes.KeyAES128Type, pkg.ActionRequest)
	if err != nil {
		log.Fatal(err)
	}
	// DecryptData returns the data with its zero padding.
	decryptedData, err := aes.DecryptData(transactionKey, ksn, encryptedData, iv, aes.KeyAES128Type, pkg.ActionRequest)
	if err != nil {
		log.Fatal(err)
	}

	nextKsn, err := pkg.GenerateNextAesKsn(ksn)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("initial key:    ", pkg.HexEncode(ik))
	fmt.Println("transaction key:", pkg.HexEncode(transactionKey))
	fmt.Println("decrypted PIN:  ", decryptedPin)
	fmt.Printf("decrypted data:  %q\n", decryptedData)
	fmt.Println("next KSN:       ", pkg.HexEncode(nextKsn))
	// Output:
	// initial key:     1273671ea26ac29afa4d1084127652a1
	// transaction key: 4f21b565bad9835e112b6465635eae44
	// decrypted PIN:   1234
	// decrypted data:  "hello\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	// next KSN:        123456789012345600000002
}
