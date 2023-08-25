package lib

import (
	"encoding/hex"
)

func HexEncode(data []byte) []byte {
	out := make([]byte, hex.DecodedLen(len(data)))

	_, err := hex.Decode(out, data)
	if err != nil {
		return nil
	}

	return out
}

func HexDecode(data []byte) []byte {
	out := make([]byte, hex.EncodedLen(len(data)))

	hex.Encode(out, data)
	return out
}
