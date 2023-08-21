package encryption

import (
	"crypto/cipher"
	"crypto/des"
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
		break
	case 24:
		tripleDESKey = append(tripleDESKey, key...)
		break
	}

	cipher, err := des.NewTripleDESCipher(tripleDESKey)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	return &DesECB{
		cipherBlock: cipher,
	}, nil
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
