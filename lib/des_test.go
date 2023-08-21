package lib

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDerivationOfInitialKey(t *testing.T) {
	ksn := HexEncode([]byte("9876543210E00001"))
	bdk := HexEncode([]byte("0123456789ABCDEFFEDCBA9876543210"))
	expect := HexEncode([]byte("6AC292FAA1315B4D858AB3A3D7D5933A"))

	ik, err := DerivationOfInitialKey(bdk, ksn)
	require.NoError(t, err)
	require.Len(t, ik, 16)
	require.Equal(t, expect, ik)
}

func TestDeriveCurrentTransactionKey(t *testing.T) {
	type TSample struct {
		ksn    []byte
		expect []byte
	}

	bdk := HexEncode([]byte("0123456789ABCDEFFEDCBA9876543210"))
	samples := []TSample{
		{
			ksn:    HexEncode([]byte("FFFF9876543210E00001")),
			expect: HexEncode([]byte("042666B49184CFA368DE9628D0397BC9")),
		},
		{
			ksn:    HexEncode([]byte("FFFF9876543210E00002")),
			expect: HexEncode([]byte("C46551CEF9FD24B0AA9AD834130D3BC7")),
		},
		{
			ksn:    HexEncode([]byte("FFFF9876543210E00003")),
			expect: HexEncode([]byte("0DF3D9422ACA56E547676D07AD6BADFA")),
		},
		{
			ksn:    HexEncode([]byte("FFFF9876543210E00004")),
			expect: HexEncode([]byte("279C0F6AEED0BE652B2C733E1383AE91")),
		},
		{
			ksn:    HexEncode([]byte("FFFF9876543210E00005")),
			expect: HexEncode([]byte("5F8DC6D2C845C125508DDC048093B83F")),
		},
	}

	for _, sample := range samples {
		ik, err := DerivationOfInitialKey(bdk, sample.ksn)
		require.NoError(t, err)
		require.Len(t, ik, 16)

		tk, err := DeriveCurrentTransactionKey(ik, sample.ksn)
		require.NoError(t, err)
		require.Len(t, tk, 16)
		require.Equal(t, sample.expect, tk)
	}

}
