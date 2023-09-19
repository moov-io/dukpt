package server

import (
	"errors"
	"github.com/moov-io/dukpt/pkg"
	"github.com/moov-io/dukpt/pkg/aes"
	"github.com/moov-io/dukpt/pkg/des"
)

type UnifiedParams struct {
	Algorithm    string
	AlgorithmKey string
	BKD          string
	KSN          string
	IK           string
	TK           string
	PIN          string
	PAN          string
	Format       string
	MacType      string
	Plaintext    string
	Ciphertext   string
	Action       string
	IV           string
}

func (p UnifiedParams) ValidateAlgorithm() error {
	if p.Algorithm != pkg.AlgorithmDes && p.Algorithm != pkg.AlgorithmAes {
		return errors.New("invalid encrypt/decrypt algorithm")
	}
	return nil
}

type WrapperCall func(params UnifiedParams) (string, error)

func InitialKey(params UnifiedParams) (string, error) {
	var buf []byte
	var err error

	if params.Algorithm == pkg.AlgorithmAes {
		buf, err = aes.DerivationOfInitialKey(pkg.HexDecode(params.BKD), pkg.HexDecode(params.KSN))

	} else {
		buf, err = des.DerivationOfInitialKey(pkg.HexDecode(params.BKD), pkg.HexDecode(params.KSN))
	}

	if err != nil {
		return "", err
	}
	return pkg.HexEncode(buf), nil
}

func TransactionKey(params UnifiedParams) (string, error) {
	var buf []byte
	var err error

	if params.Algorithm == pkg.AlgorithmAes {
		buf, err = aes.DeriveCurrentTransactionKey(pkg.HexDecode(params.IK), pkg.HexDecode(params.KSN))
	} else {
		buf, err = des.DeriveCurrentTransactionKey(pkg.HexDecode(params.IK), pkg.HexDecode(params.KSN))
	}

	if err != nil {
		return "", err
	}
	return pkg.HexEncode(buf), nil
}

func EncryptPin(params UnifiedParams) (string, error) {
	var buf []byte
	var err error

	if params.Algorithm == pkg.AlgorithmAes {
		buf, err = aes.EncryptPin(pkg.HexDecode(params.TK), pkg.HexDecode(params.KSN), params.PIN, params.PAN, params.AlgorithmKey)
	} else {
		buf, err = des.EncryptPin(pkg.HexDecode(params.TK), params.PIN, params.PAN, params.Format)
	}

	if err != nil {
		return "", err
	}
	return pkg.HexEncode(buf), nil
}

func DecryptPin(params UnifiedParams) (string, error) {
	var buf string
	var err error

	if params.Algorithm == pkg.AlgorithmAes {
		buf, err = aes.DecryptPin(pkg.HexDecode(params.TK), pkg.HexDecode(params.KSN), pkg.HexDecode(params.PIN), params.PAN, params.AlgorithmKey)
	} else {
		buf, err = des.DecryptPin(pkg.HexDecode(params.TK), pkg.HexDecode(params.PIN), params.PAN, params.Format)
	}

	if err != nil {
		return "", err
	}
	return buf, nil
}

func GenerateMac(params UnifiedParams) (string, error) {
	var buf []byte
	var err error

	if params.Algorithm == pkg.AlgorithmAes {
		if params.MacType != pkg.MaxTypeCmac && params.MacType != pkg.MaxTypeHmac {
			return "", errors.New("invalid mac type")
		}
		if params.MacType == pkg.MaxTypeCmac {
			buf, err = aes.GenerateCMAC(pkg.HexDecode(params.TK), pkg.HexDecode(params.KSN), params.Plaintext, params.AlgorithmKey, params.Action)
		} else {
			buf, err = aes.GenerateHMAC(pkg.HexDecode(params.TK), pkg.HexDecode(params.KSN), params.Plaintext, params.AlgorithmKey, params.Action)
		}
	} else {
		buf, err = des.GenerateMac(pkg.HexDecode(params.TK), params.Plaintext, params.Action)
	}

	if err != nil {
		return "", err
	}
	return pkg.HexEncode(buf), nil
}

func EncryptData(params UnifiedParams) (string, error) {
	var buf []byte
	var err error

	if params.Algorithm == pkg.AlgorithmAes {
		buf, err = aes.EncryptData(pkg.HexDecode(params.TK), pkg.HexDecode(params.KSN), pkg.HexDecode(params.IV), params.Plaintext, params.AlgorithmKey, params.Action)
	} else {
		buf, err = des.EncryptData(pkg.HexDecode(params.TK), pkg.HexDecode(params.IV), params.Plaintext, params.Action)
	}

	if err != nil {
		return "", err
	}
	return pkg.HexEncode(buf), nil
}

func DecryptData(params UnifiedParams) (string, error) {
	var buf string
	var err error

	if params.Algorithm == pkg.AlgorithmAes {
		buf, err = aes.DecryptData(pkg.HexDecode(params.TK), pkg.HexDecode(params.KSN), pkg.HexDecode(params.Ciphertext), pkg.HexDecode(params.IV), params.AlgorithmKey, params.Action)
	} else {
		buf, err = des.DecryptData(pkg.HexDecode(params.TK), pkg.HexDecode(params.Ciphertext), pkg.HexDecode(params.IV), params.Action)
	}

	if err != nil {
		return "", err
	}
	return buf, nil
}
