package pkg

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGenerateNextKsn_DoesNotModifyInput: both generators used to write the new
// counter into the caller's KSN (AES via append on ksn[:8], which keeps ksn's
// capacity; DES by assigning into ksn), so a caller keeping the previous KSN
// for a retry or a log entry silently lost it.
func TestGenerateNextKsn_DoesNotModifyInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		ksn  string
		next func([]byte) ([]byte, error)
		want string
	}{
		{"aes", "123456789012345600000001", GenerateNextAesKsn, "123456789012345600000002"},
		{"des", "ffff9876543210e00001", GenerateNextDesKsn, "ffff9876543210e00002"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ksn := HexDecode(tc.ksn)
			next, err := tc.next(ksn)
			require.NoError(t, err)
			require.Equal(t, tc.want, HexEncode(next))
			require.Equal(t, tc.ksn, HexEncode(ksn), "input KSN was modified")

			next[0] ^= 0xFF
			require.Equal(t, tc.ksn, HexEncode(ksn), "result shares the input's array")
		})
	}
}

// TestGenerateNextKsn_RejectsWrongLength: an AES KSN is exactly 12 bytes (with
// any other length the counter is read from the wrong bytes and an 8-byte
// input was accepted); a DES KSN shorter than its 3 counter bytes panicked.
func TestGenerateNextKsn_RejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 5, 8, 11, 13} {
		_, err := GenerateNextAesKsn(make([]byte, n))
		require.Error(t, err, "AES length %d", n)
	}
	for _, n := range []int{0, 2} {
		_, err := GenerateNextDesKsn(make([]byte, n))
		require.Error(t, err, "DES length %d", n)
	}
}
