package encryption

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

type DesECB struct {
	cipherBlock cipher.Block
}

func NewDesECB(key []byte) (*DesECB, error) {
	cipher, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	return &DesECB{
		cipherBlock: cipher,
	}, nil
}

func (a *DesECB) Encrypt(plainText []byte) ([]byte, error) {
	if len(plainText) != des.BlockSize {
		return nil, fmt.Errorf("plain text length must be %d bytes", des.BlockSize)
	}

	cipherText := make([]byte, len(plainText))
	a.cipherBlock.Encrypt(cipherText, plainText)
	return cipherText, nil
}

func (a *DesECB) Decrypt(cipherText []byte) ([]byte, error) {
	if len(cipherText) != des.BlockSize {
		return nil, fmt.Errorf("cipher text length must be %d bytes", des.BlockSize)
	}

	plainText := make([]byte, len(cipherText))
	a.cipherBlock.Decrypt(plainText, cipherText)
	return plainText, nil
}
