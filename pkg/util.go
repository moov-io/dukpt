package pkg

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const (
	AlgorithmDes = "des"
	AlgorithmAes = "aes"
	MaxTypeCmac  = "cmac"
	MaxTypeHmac  = "hmac"
)

func HexDecode(data string) []byte {
	if len(data) == 0 {
		return nil
	}

	out := make([]byte, hex.DecodedLen(len(data)))
	_, err := hex.Decode(out, []byte(data))
	if err != nil {
		return nil
	}

	return out
}

func HexEncode(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	out := make([]byte, hex.EncodedLen(len(data)))
	hex.Encode(out, data)
	return string(out)
}

func GetAesTcFromKsn(ksn []byte) uint32 {
	var tc uint32

	if len(ksn) > 4 {
		tcBits := ksn[len(ksn)-4:]
		tc = binary.BigEndian.Uint32(tcBits)
	}

	return tc
}

func GenerateNextAesKsn(ksn []byte) ([]byte, error) {
	var tcMax uint32 = 0xFFFF0000
	tc := GetAesTcFromKsn(ksn)

	if tc > tcMax {
		return nil, errors.New("transaction already counter exhausted")
	}

	tc++
	for tc <= tcMax {
		bitCount := 0
		for tmp := tc; tmp != 0; bitCount++ {
			// Clear least significant bit
			tmp &= tmp - 1
		}

		if bitCount <= 16 {
			// Current transaction counter is valid
			break
		}

		lsbSetBit := tc & ^(tc - 1)
		tc += lsbSetBit
	}

	tcMsb := make([]byte, 4)
	binary.BigEndian.PutUint32(tcMsb, tc)

	result := append(ksn[:8], tcMsb...)
	return result, nil
}

func GetDesTcFromKsn(ksn []byte) uint32 {
	var tc uint32

	if len(ksn) > 3 {
		length := len(ksn)
		tc = uint32(ksn[length-1]) | uint32(ksn[length-2])<<8 | (uint32(ksn[length-3])&0x1f)<<16
	}

	return tc
}

func GenerateNextDesKsn(ksn []byte) ([]byte, error) {
	var tcMax uint32 = 0x1FF800
	tc := GetDesTcFromKsn(ksn)

	if tc > tcMax {
		return nil, errors.New("transaction already counter exhausted")
	}

	tc++
	tc &= 0x1FFFFF
	for tc <= tcMax {
		bitCount := 0
		for tmp := tc; tmp != 0; bitCount++ {
			// Clear least significant bit
			tmp &= tmp - 1
		}

		if bitCount <= 10 {
			// Current transaction counter is valid
			break
		}

		lsbSetBit := tc & ^(tc - 1)
		tc += lsbSetBit
	}

	if tc > tcMax {
		return nil, errors.New("transaction already counter exhausted")
	}

	{
		length := len(ksn)
		ksn[length-1] = byte(tc)
		ksn[length-2] = byte(tc >> 8)
		ksn[length-3] &= 0xE0
		ksn[length-3] |= byte(tc >> 16)
	}

	return ksn, nil
}

func IsValidAesKsn(ksn []byte) bool {
	tc := GetAesTcFromKsn(ksn)

	if tc == 0 {
		return false
	}

	bitCount := 0
	for tmp := tc; tmp != 0; bitCount++ {
		// Clear least significant bit
		tmp &= tmp - 1
	}

	return bitCount <= 16
}

const (
	ActionRequest  = "request"
	ActionResponse = "response"
)
