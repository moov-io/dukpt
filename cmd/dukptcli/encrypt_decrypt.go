package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/moov-io/dukpt/pkg"
	"github.com/moov-io/dukpt/pkg/aes"
	"github.com/moov-io/dukpt/pkg/des"
)

type cliParams struct {
	Algorithm        string
	AlgorithmKeyType string
	BKD              string
	KSN              string
	KID              string
	IK               string
	TK               string
	PIN              string
	PAN              string
	Format           string
	MacType          string
	Plaintext        string
	Ciphertext       string
	Action           string
	IV               string
}

func (p cliParams) ValidateAlgorithm() error {
	if p.Algorithm != "des" && p.Algorithm != "ase" {
		return errors.New("invalid encrypt/decrypt algorithm")
	}
	return nil
}

type funcInf func(params cliParams) (string, error)

func initialKey(params cliParams) (string, error) {
	var buf []byte
	var err error

	if params.Algorithm == "aes" {
		buf, err = aes.DerivationOfInitialKey(pkg.HexDecode(params.BKD), pkg.HexDecode(params.KID))

	} else {
		buf, err = des.DerivationOfInitialKey(pkg.HexDecode(params.BKD), pkg.HexDecode(params.KSN))
	}

	if err != nil {
		return "", err
	}
	return pkg.HexEncode(buf), nil
}

func transactionKey(params cliParams) (string, error) {
	var buf []byte
	var err error

	if params.Algorithm == "aes" {
		buf, err = aes.DeriveCurrentTransactionKey(pkg.HexDecode(params.IK), pkg.HexDecode(params.KSN))
	} else {
		buf, err = des.DeriveCurrentTransactionKey(pkg.HexDecode(params.IK), pkg.HexDecode(params.KSN))
	}

	if err != nil {
		return "", err
	}
	return pkg.HexEncode(buf), nil
}

func encryptPin(params cliParams) (string, error) {
	var buf []byte
	var err error

	if params.Algorithm == "aes" {
		buf, err = aes.EncryptPin(pkg.HexDecode(params.TK), pkg.HexDecode(params.KSN), params.PIN, params.PAN, params.AlgorithmKeyType)
	} else {
		buf, err = des.EncryptPin(pkg.HexDecode(params.TK), params.PIN, params.PAN, params.Format)
	}

	if err != nil {
		return "", err
	}
	return pkg.HexEncode(buf), nil
}

func decryptPin(params cliParams) (string, error) {
	var buf string
	var err error

	if params.Algorithm == "aes" {
		buf, err = aes.DecryptPin(pkg.HexDecode(params.TK), pkg.HexDecode(params.KSN), pkg.HexDecode(params.PIN), params.PAN, params.AlgorithmKeyType)
	} else {
		buf, err = des.DecryptPin(pkg.HexDecode(params.TK), pkg.HexDecode(params.PIN), params.PAN, params.Format)
	}

	if err != nil {
		return "", err
	}
	return buf, nil
}

func generateMac(params cliParams) (string, error) {
	var buf []byte
	var err error

	if params.Algorithm == "aes" {
		if params.MacType != "cmac" && params.MacType != "hmac" {
			return "", errors.New("invalid mac type")
		}
		if params.MacType == "cmac" {
			buf, err = aes.GenerateCMAC(pkg.HexDecode(params.TK), pkg.HexDecode(params.KSN), params.Plaintext, params.AlgorithmKeyType, params.Action)
		} else {
			buf, err = aes.GenerateHMAC(pkg.HexDecode(params.TK), pkg.HexDecode(params.KSN), params.Plaintext, params.AlgorithmKeyType, params.Action)
		}
	} else {
		buf, err = des.GenerateMac(pkg.HexDecode(params.TK), params.Plaintext, params.Action)
	}

	if err != nil {
		return "", err
	}
	return pkg.HexEncode(buf), nil
}

func encryptData(params cliParams) (string, error) {
	var buf []byte
	var err error

	if params.Algorithm == "aes" {
		buf, err = aes.EncryptData(pkg.HexDecode(params.TK), pkg.HexDecode(params.KSN), pkg.HexDecode(params.IV), params.Plaintext, params.AlgorithmKeyType, params.Action)
	} else {
		buf, err = des.EncryptData(pkg.HexDecode(params.TK), pkg.HexDecode(params.IV), params.Plaintext, params.Action)
	}

	if err != nil {
		return "", err
	}
	return pkg.HexEncode(buf), nil
}

func decryptData(params cliParams) (string, error) {
	var buf string
	var err error

	if params.Algorithm == "aes" {
		buf, err = aes.DecryptData(pkg.HexDecode(params.TK), pkg.HexDecode(params.KSN), pkg.HexDecode(params.IV), pkg.HexDecode(params.Ciphertext), params.AlgorithmKeyType, params.Action)
	} else {
		buf, err = des.DecryptData(pkg.HexDecode(params.TK), pkg.HexDecode(params.IV), pkg.HexDecode(params.Ciphertext), params.Action)
	}

	if err != nil {
		return "", err
	}
	return buf, nil
}

func makeFuncCall(f funcInf, params cliParams) {
	if err := params.ValidateAlgorithm(); err != nil {
		fmt.Printf("%s\n", err.Error())
		os.Exit(2)
	}

	result, err := f(params)
	if err != nil {
		fmt.Printf("%s\n", err.Error())
		os.Exit(2)
	}

	fmt.Printf("RESULT: %s\n", result)
}
