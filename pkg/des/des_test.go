package des

import (
	"fmt"
	"testing"

	"github.com/moov-io/dukpt/pkg"
	"github.com/stretchr/testify/require"
)

type SequenceItem struct {
	Ksn         []byte
	CurrentKey  []byte
	PinEnc      []byte
	DataReqEnc  []byte
	DataResEnc  []byte
	RequestMac  []byte
	ResponseMac []byte
}

// A.4.2 Initial Sequence
var InitialSequence = []SequenceItem{
	{
		Ksn:         pkg.HexDecode("FFFF9876543210E00001"),
		CurrentKey:  pkg.HexDecode("042666B49184CFA368DE9628D0397BC9"),
		PinEnc:      pkg.HexDecode("1B9C1845EB993A7A"),
		DataReqEnc:  pkg.HexDecode("FC0D53B7EA1FDA9EE68AAF2E70D9B9506229BE2AA993F04F"),
		DataResEnc:  pkg.HexDecode("1FCC89AF66222F27B903898BB2BC8589CDBFDE5EC6AFCC25"),
		RequestMac:  pkg.HexDecode("9CCC78173FC4FB64"),
		ResponseMac: pkg.HexDecode("20364223C1FF00FA"),
	},
	{
		Ksn:         pkg.HexDecode("FFFF9876543210E00002"),
		CurrentKey:  pkg.HexDecode("C46551CEF9FD24B0AA9AD834130D3BC7"),
		PinEnc:      pkg.HexDecode("10A01C8D02C69107"),
		DataReqEnc:  pkg.HexDecode("A2B4E70F846E63D68775B7215EB4563DFD3037244C61CC13"),
		DataResEnc:  pkg.HexDecode("5B692A6B1FDD5E25B0DEFAFDE1672E402F8011360CFF3508"),
		RequestMac:  pkg.HexDecode("F608A9BCA6FFC311"),
		ResponseMac: pkg.HexDecode("D1FCA6BEF05D24D2"),
	},
	{
		Ksn:         pkg.HexDecode("FFFF9876543210E00003"),
		CurrentKey:  pkg.HexDecode("0DF3D9422ACA56E547676D07AD6BADFA"),
		PinEnc:      pkg.HexDecode("18DC07B94797B466"),
		DataReqEnc:  pkg.HexDecode("BD751E65F10E75B6C1D5B1D283496A36C2DE21D993C387A7"),
		DataResEnc:  pkg.HexDecode("345992D4163E4926C927BFD8ABD5D76F087A9CE81D5A27B8"),
		RequestMac:  pkg.HexDecode("20B59A4FEAC937E3"),
		ResponseMac: pkg.HexDecode("BAD4CC9CC2AE326C"),
	},
	{
		Ksn:         pkg.HexDecode("FFFF9876543210E00004"),
		CurrentKey:  pkg.HexDecode("279C0F6AEED0BE652B2C733E1383AE91"),
		PinEnc:      pkg.HexDecode("0BC79509D5645DF7"),
		DataReqEnc:  pkg.HexDecode("1118F50947441BBDA3C8C70220021A12EC31CC473F7215F4"),
		DataResEnc:  pkg.HexDecode("418C7413576C0D1819E785D3807AF32334231FDEC23414DB"),
		RequestMac:  pkg.HexDecode("C7BFA6CC44161828"),
		ResponseMac: pkg.HexDecode("1EB08AEECE6FF0C2"),
	},
	{
		Ksn:         pkg.HexDecode("FFFF9876543210E00005"),
		CurrentKey:  pkg.HexDecode("5F8DC6D2C845C125508DDC048093B83F"),
		PinEnc:      pkg.HexDecode("5BC0AF22AD87B327"),
		DataReqEnc:  pkg.HexDecode("9FD7BD1EC28845ACA93367A9DA9317BD555C6B33AE22D365"),
		DataResEnc:  pkg.HexDecode("7D4C109E49E83355A556AE949EED359F4404E7A2F0167C00"),
		RequestMac:  pkg.HexDecode("0202B96339022058"),
		ResponseMac: pkg.HexDecode("5CBE3E81D1D2A0FB"),
	},
}

func TestDerivationOfInitialKey(t *testing.T) {
	Ksn := pkg.HexDecode("9876543210E00001")
	bdk := pkg.HexDecode("0123456789ABCDEFFEDCBA9876543210")
	expect := pkg.HexDecode("6AC292FAA1315B4D858AB3A3D7D5933A")

	ik, err := DerivationOfInitialKey(bdk, Ksn)
	require.NoError(t, err)
	require.Len(t, ik, 16)
	require.Equal(t, expect, ik)
}

func TestDeriveCurrentTransactionKey(t *testing.T) {
	bdk := pkg.HexDecode(("0123456789ABCDEFFEDCBA9876543210"))
	pin := "1234"
	pan := "4012345678909"
	FormatVersion := "ISO-0"
	data := "4012345678909D987"

	for index, item := range InitialSequence {
		t.Run(fmt.Sprintf("Sequence #%d KSN: %s", index+1, pkg.HexEncode(item.Ksn)), func(t *testing.T) {
			ik, err := DerivationOfInitialKey(bdk, item.Ksn)
			require.NoError(t, err)
			require.Len(t, ik, 16)

			ck, err := DeriveCurrentTransactionKey(ik, item.Ksn)
			require.NoError(t, err)
			require.Len(t, ck, 16)
			require.Equal(t, item.CurrentKey, ck)

			encryptedPin, err := EncryptPin(ck, pin, pan, FormatVersion)
			require.NoError(t, err)
			require.Len(t, encryptedPin, 8)
			require.Equal(t, item.PinEnc, encryptedPin)

			decryptedPin, err := DecryptPin(ck, encryptedPin, pan, FormatVersion)
			require.NoError(t, err)
			require.Len(t, decryptedPin, 4)
			require.Equal(t, pin, decryptedPin)

			encReqData, err := EncryptData(ck, nil, data, pkg.ActionRequest)
			require.NoError(t, err)
			require.Equal(t, item.DataReqEnc, encReqData)

			decReqData, err := DecryptData(ck, encReqData, nil, pkg.ActionRequest)
			require.NoError(t, err)
			require.Len(t, decReqData, 24)
			require.Equal(t, data, decReqData[:len(data)])

			encResData, err := EncryptData(ck, nil, data, pkg.ActionResponse)
			require.NoError(t, err)
			require.Equal(t, item.DataResEnc, encResData)

			decResData, err := DecryptData(ck, encResData, nil, pkg.ActionResponse)
			require.NoError(t, err)
			require.Len(t, decResData, 24)
			require.Equal(t, data, decResData[:len(data)])

			encReqMac, err := GenerateMac(ck, data, pkg.ActionRequest)
			require.NoError(t, err)
			require.Equal(t, item.RequestMac, encReqMac)

			encResMac, err := GenerateMac(ck, data, pkg.ActionResponse)
			require.NoError(t, err)
			require.Equal(t, item.ResponseMac, encResMac)
		})
	}
}
