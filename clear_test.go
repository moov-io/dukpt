package dukpt

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClear(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 24)
	Clear(key)
	require.Equal(t, make([]byte, 24), key)

	buf := bytes.Repeat([]byte{0x5A}, 32)
	Clear(buf[:16:32][:32])
	require.Equal(t, make([]byte, 32), buf)

	Clear(nil)
}
