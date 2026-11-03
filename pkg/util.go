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

// GenerateNextAesKsn returns the next valid AES DUKPT KSN after ksn: the same
// 8-byte Initial Key ID with the next transaction counter that has at most 16
// bits set (ANSI X9.24-3). ksn must be the 12-byte KSN; it is not modified, and
// the result is a new slice, so a caller can keep the previous KSN.
func GenerateNextAesKsn(ksn []byte) ([]byte, error) {
	// A 12-byte KSN is the 8-byte Initial Key ID plus the 4-byte counter. With
	// any other length the counter would be read from the wrong bytes.
	if len(ksn) != 12 {
		return nil, errors.New("ksn length must be 12 bytes")
	}

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

	// A new slice: append(ksn[:8], ...) would write the counter into the
	// caller's array, since ksn[:8] keeps ksn's capacity.
	result := make([]byte, 0, 12)
	result = append(result, ksn[:8]...)
	result = append(result, tcMsb...)
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

// GenerateNextDesKsn returns the next valid TDES DUKPT KSN after ksn, with the
// next 21-bit transaction counter that has at most 10 bits set. ksn is not
// modified; the result is a new slice, so a caller can keep the previous KSN.
func GenerateNextDesKsn(ksn []byte) ([]byte, error) {
	// The counter occupies the low 21 bits of the last 3 bytes.
	if len(ksn) < 3 {
		return nil, errors.New("ksn length must be at least 3 bytes")
	}

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

	result := make([]byte, len(ksn))
	copy(result, ksn)
	{
		// tc is masked to 21 bits above; pack those bits into the trailing KSN bytes.
		// Explicit & masks keep conversions within byte range for static analysis (gosec G115).
		length := len(result)
		result[length-1] = byte(tc & 0xFF)
		result[length-2] = byte((tc >> 8) & 0xFF)
		result[length-3] &= 0xE0
		result[length-3] |= byte((tc >> 16) & 0x1F)
	}

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

	return bitCount <= 16
}

const (
	ActionRequest  = "request"
	ActionResponse = "response"
)
