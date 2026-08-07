package encryption

import (
	"crypto/cipher"
	// DES/3DES are required by ANSI X9.24 DUKPT; not for general-purpose crypto.
	"crypto/des" //nolint:gosec
	"errors"
	"fmt"
	"strconv"
)

type DesECB struct {
	cipherBlock cipher.Block
}

func NewTripleDesECB(key []byte) (*DesECB, error) {
	var tripleDESKey []byte

	k := len(key)
	switch k {
	default:
		return nil, errors.New("creating cipher: invalid key size " + strconv.Itoa(k))
	case 16:
		tripleDESKey = append(tripleDESKey, key[:16]...)
		tripleDESKey = append(tripleDESKey, key[:8]...)
	case 24:
		tripleDESKey = append(tripleDESKey, key...)
	}

	// codeql[go/weak-cryptographic-algorithm] DES/3DES required by ANSI X9.24 DUKPT
	cp, err := des.NewTripleDESCipher(tripleDESKey) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	return &DesECB{
		cipherBlock: cp,
	}, nil
}

func NewDesECB(key []byte) (*DesECB, error) {
	// codeql[go/weak-cryptographic-algorithm] DES required by ANSI X9.24 DUKPT
	cp, err := des.NewCipher(key) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	return &DesECB{
		cipherBlock: cp,
	}, nil
}

func (a *DesECB) Encrypt(plainText []byte) ([]byte, error) {
	if len(plainText) != des.BlockSize {
		return nil, fmt.Errorf("plain text length must be %d bytes", des.BlockSize)
	}

	cipherText := make([]byte, len(plainText))
	// codeql[go/weak-cryptographic-algorithm] DES/3DES required by ANSI X9.24 DUKPT
	a.cipherBlock.Encrypt(cipherText, plainText)
	return cipherText, nil
}

func (a *DesECB) Decrypt(cipherText []byte) ([]byte, error) {
	if len(cipherText) != des.BlockSize {
		return nil, fmt.Errorf("cipher text length must be %d bytes", des.BlockSize)
	}

	plainText := make([]byte, len(cipherText))
	// codeql[go/weak-cryptographic-algorithm] DES/3DES required by ANSI X9.24 DUKPT
	a.cipherBlock.Decrypt(plainText, cipherText)
	return plainText, nil
}

func (a *DesECB) GetBlock() cipher.Block {
	if a == nil {
		return nil
	}
	return a.cipherBlock
}
