package server

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

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
	p = p.normalize()
	if p.Algorithm != pkg.AlgorithmDes && p.Algorithm != pkg.AlgorithmAes {
		return errors.New("invalid encrypt/decrypt algorithm")
	}
	return nil
}

type WrapperCall func(params UnifiedParams) (string, error)

// pkg/aes HMAC derivation requires HMAC* key types; CMAC requires AES*.
func (p UnifiedParams) normalize() UnifiedParams {
	p.Algorithm = strings.ToLower(strings.TrimSpace(p.Algorithm))
	p.AlgorithmKey = strings.ToUpper(strings.TrimSpace(p.AlgorithmKey))
	p.MacType = strings.ToLower(strings.TrimSpace(p.MacType))

	if p.Algorithm == pkg.AlgorithmAes {
		if p.AlgorithmKey == "" {
			p.AlgorithmKey = aes.KeyAES128Type
		}
		if p.MacType == pkg.MaxTypeHmac && strings.HasPrefix(p.AlgorithmKey, "AES") {
			p.AlgorithmKey = "HMAC" + strings.TrimPrefix(p.AlgorithmKey, "AES")
		}
		if p.MacType == pkg.MaxTypeCmac && strings.HasPrefix(p.AlgorithmKey, "HMAC") {
			p.AlgorithmKey = "AES" + strings.TrimPrefix(p.AlgorithmKey, "HMAC")
		}
	}
	return p
}

// Empty hex is nil so missing keys keep the usual length errors.
func decodeHex(name, value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	out, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid hex value for %s: %w", name, err)
	}
	return out, nil
}

func decodeHexFields(fields ...string) ([][]byte, error) {
	out := make([][]byte, 0, len(fields)/2)
	for i := 0; i+1 < len(fields); i += 2 {
		b, err := decodeHex(fields[i], fields[i+1])
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func InitialKey(params UnifiedParams) (string, error) {
	params = params.normalize()
	v, err := decodeHexFields("bdk", params.BKD, "ksn", params.KSN)
	if err != nil {
		return "", err
	}
	bdk, ksn := v[0], v[1]

	var buf []byte
	if params.Algorithm == pkg.AlgorithmAes {
		buf, err = aes.DerivationOfInitialKey(bdk, ksn)
	} else {
		buf, err = des.DerivationOfInitialKey(bdk, ksn)
	}

	if err != nil {
		return "", err
	}
	return pkg.HexEncode(buf), nil
}

func TransactionKey(params UnifiedParams) (string, error) {
	params = params.normalize()
	v, err := decodeHexFields("ik", params.IK, "ksn", params.KSN)
	if err != nil {
		return "", err
	}
	ik, ksn := v[0], v[1]

	var buf []byte
	if params.Algorithm == pkg.AlgorithmAes {
		buf, err = aes.DeriveCurrentTransactionKey(ik, ksn)
	} else {
		buf, err = des.DeriveCurrentTransactionKey(ik, ksn)
	}

	if err != nil {
		return "", err
	}
	return pkg.HexEncode(buf), nil
}

func EncryptPin(params UnifiedParams) (string, error) {
	params = params.normalize()
	v, err := decodeHexFields("tk", params.TK, "ksn", params.KSN)
	if err != nil {
		return "", err
	}
	tk, ksn := v[0], v[1]

	var buf []byte
	if params.Algorithm == pkg.AlgorithmAes {
		buf, err = aes.EncryptPin(tk, ksn, params.PIN, params.PAN, params.AlgorithmKey)
	} else {
		buf, err = des.EncryptPin(tk, params.PIN, params.PAN, params.Format)
	}

	if err != nil {
		return "", err
	}
	return pkg.HexEncode(buf), nil
}

func DecryptPin(params UnifiedParams) (string, error) {
	params = params.normalize()
	v, err := decodeHexFields("tk", params.TK, "ksn", params.KSN, "pin", params.PIN)
	if err != nil {
		return "", err
	}
	tk, ksn, pin := v[0], v[1], v[2]

	var buf string
	if params.Algorithm == pkg.AlgorithmAes {
		buf, err = aes.DecryptPin(tk, ksn, pin, params.PAN, params.AlgorithmKey)
	} else {
		buf, err = des.DecryptPin(tk, pin, params.PAN, params.Format)
	}

	if err != nil {
		return "", err
	}
	return buf, nil
}

func GenerateMac(params UnifiedParams) (string, error) {
	params = params.normalize()
	v, err := decodeHexFields("tk", params.TK, "ksn", params.KSN)
	if err != nil {
		return "", err
	}
	tk, ksn := v[0], v[1]

	var buf []byte
	if params.Algorithm == pkg.AlgorithmAes {
		if params.MacType != pkg.MaxTypeCmac && params.MacType != pkg.MaxTypeHmac {
			return "", errors.New("invalid mac type")
		}
		if params.MacType == pkg.MaxTypeCmac {
			buf, err = aes.GenerateCMAC(tk, ksn, params.Plaintext, params.AlgorithmKey, params.Action)
		} else {
			buf, err = aes.GenerateHMAC(tk, ksn, params.Plaintext, params.AlgorithmKey, params.Action)
		}
	} else {
		buf, err = des.GenerateMac(tk, params.Plaintext, params.Action)
	}

	if err != nil {
		return "", err
	}
	return pkg.HexEncode(buf), nil
}

func EncryptData(params UnifiedParams) (string, error) {
	params = params.normalize()
	v, err := decodeHexFields("tk", params.TK, "ksn", params.KSN, "iv", params.IV)
	if err != nil {
		return "", err
	}
	tk, ksn, iv := v[0], v[1], v[2]

	var buf []byte
	if params.Algorithm == pkg.AlgorithmAes {
		buf, err = aes.EncryptData(tk, ksn, iv, params.Plaintext, params.AlgorithmKey, params.Action)
	} else {
		buf, err = des.EncryptData(tk, iv, params.Plaintext, params.Action)
	}

	if err != nil {
		return "", err
	}
	return pkg.HexEncode(buf), nil
}

func DecryptData(params UnifiedParams) (string, error) {
	params = params.normalize()
	v, err := decodeHexFields("tk", params.TK, "ksn", params.KSN, "ciphertext", params.Ciphertext, "iv", params.IV)
	if err != nil {
		return "", err
	}
	tk, ksn, ciphertext, iv := v[0], v[1], v[2], v[3]

	var buf string
	if params.Algorithm == pkg.AlgorithmAes {
		buf, err = aes.DecryptData(tk, ksn, ciphertext, iv, params.AlgorithmKey, params.Action)
	} else {
		buf, err = des.DecryptData(tk, ciphertext, iv, params.Action)
	}

	if err != nil {
		return "", err
	}
	return buf, nil
}
