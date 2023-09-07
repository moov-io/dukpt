package pkg

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
)

func HexDecode(data string) []byte {
	out := make([]byte, hex.DecodedLen(len(data)))

	_, err := hex.Decode(out, []byte(data))
	if err != nil {
		return nil
	}

	return out
}

func HexEncode(data []byte) string {
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

func GenerateNextKsn(ksn []byte) ([]byte, error) {
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

	if bitCount > 16 {
		return false
	}

	return true
}

const (
	ActionRequest  = "request"
	ActionResponse = "response"
)
