package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The wrapper clears its byte copies of the PIN and PAN; the HTTP round trip
// still returns the PIN.
func TestWrapper_PinRoundTrip(t *testing.T) {
	params := UnifiedParams{
		Algorithm: "des",
		TK:        "0DF3D9422ACA56E547676D07AD6BADFA",
		PIN:       "1234",
		PAN:       "4012345678909",
		Format:    "ISO-0",
	}
	encrypted, err := EncryptPin(params)
	require.NoError(t, err)

	params.PIN = encrypted
	pin, err := DecryptPin(params)
	require.NoError(t, err)
	require.Equal(t, "1234", pin)
}
