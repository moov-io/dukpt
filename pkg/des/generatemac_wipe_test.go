package des

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// GenerateMac clears its zero-padded copy of the message.
func TestGenerateMac_ClearsPaddedMessage(t *testing.T) {
	message := "4012345678909D987"
	padded := make([]byte, 24)
	copy(padded, message)

	r := recordWipes(t)
	_, err := GenerateMac(wipeTestTK, message, "request")
	require.NoError(t, err)
	r.requireWiped(t, padded, "padded message")
	r.requireAllZero(t)
}
