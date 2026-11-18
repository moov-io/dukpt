package cbc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIV(t *testing.T) {
	for _, tc := range []struct {
		name string
		iv   []byte
		want []byte
	}{
		{"nil", nil, make([]byte, 8)},
		{"empty", []byte{}, make([]byte, 8)},
		{"short", []byte{1, 2, 3}, []byte{1, 2, 3, 0, 0, 0, 0, 0}},
		{"exact", []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{"long", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{1, 2, 3, 4, 5, 6, 7, 8}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, IV(tc.iv, 8))
		})
	}
}

// A short IV with spare capacity must not be padded in place: the bytes past
// its length belong to the caller.
func TestIV_DoesNotWriteIntoCallerBuffer(t *testing.T) {
	buf := []byte{1, 2, 3, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	out := IV(buf[:3], 8)
	require.Equal(t, []byte{1, 2, 3, 0, 0, 0, 0, 0}, out)
	require.Equal(t, []byte{1, 2, 3, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}, buf)

	out[0] = 0xFF
	require.Equal(t, byte(1), buf[0], "the result must not share the caller's array")
}
