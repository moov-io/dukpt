package aes

import (
	"fmt"
	"strings"
	"testing"

	"github.com/moov-io/dukpt/pkg"
	"github.com/stretchr/testify/require"
)

type SequenceItem struct {
	Ksn          string
	CurrentKey   string
	CMACRequest  string
	CMACResponse string
	HMACRequest  string
	HMACResponse string
	DataRequest  string
	DataResponse string
}

var InitialSequence = []SequenceItem{
	{
		Ksn:          "123456789012345600000001",
		CurrentKey:   "4F21B565BAD9835E112B6465635EAE44",
		CMACRequest:  "A2EB5C1C35809E58404E873C3C411E31",
		CMACResponse: "DD4E1895FD9BF53D8DAF25568ABF551D",
		HMACRequest:  "B6F8B3159CD4E140159DA87A68C0FB7AF2F123D222662E98988C76386E8E8A02",
		HMACResponse: "DDE7CB7BDE05AC9A934919B5D94C37954F2376BAF5D45031A56FE74D94C4B64D",
		DataRequest:  "E5AFA5B408A3310E3D779C8A9A2AE29448BD5B4232582090DB703AF647205A79",
		DataResponse: "84904DFC6B5201A4F1FE2EAA49E70B8C01838EF53030790FF785D630AB3916B4",
	},
	{
		Ksn:          "123456789012345600000002",
		CurrentKey:   "2F34D68DE10F68D38091A73B9E7C437C",
		CMACRequest:  "4D104704C53491A60944193DCAF6B411",
		CMACResponse: "008CEAAE2B913BEEE76209EE9406DAC1",
		HMACRequest:  "A884FD458692820E8458AD9FF4FCE58D6B809AB3AE617AE1FC6B70E9E9C12B08",
		HMACResponse: "32C4EEBF5FB820C4E90A580C0769E5BF8188007191AFAEF53F7C585B03285314",
		DataRequest:  "A17A9658EE0F451D6CA11B65B592EF9C5F90BB175D926F1457B63B3273042476",
		DataResponse: "699ED7BC85994F1C11DE1C40177A629530E85262EA0B02FB80771255DC1F65B6",
	},
	{
		Ksn:          "123456789012345600000003",
		CurrentKey:   "031504E530365CF81264238540518318",
		CMACRequest:  "6A18904AA8E966A03505F5EEBDAEBD82",
		CMACResponse: "40CB2F0C2E043D060063FAA916A849E1",
		HMACRequest:  "5CCB50FB8001C07C51191502BFC7586E165219F59D87938C8A7A84D41AF44F18",
		HMACResponse: "255E08E91BB5AFFD26C695110FAB5167AB36C9A3C61C78BD2401292A8EFE7C0A",
		DataRequest:  "E289C32A084A39419A6C147DE40B53A67BABE2BD22DC3D5EE09B002E83B93ACE",
		DataResponse: "0F440D9321C1ABBEF9CA7008B40CF18B3045A84D5435D6CF9A4955E3451C49E9",
	},
	{
		Ksn:          "123456789012345600000004",
		CurrentKey:   "0EEFC7ADA628BA68878DA9165A8A1887",
		CMACRequest:  "77BBD3FB827158B9B12880B0794D1C74",
		CMACResponse: "51FDE192BC484F769AA0A86F8BC5CB30",
		HMACRequest:  "5E3C734C41496A10130BE415CBDB8E4F9027250997803DC742D4988123C2963F",
		HMACResponse: "6493E4DB82E4ACFB3AA3830EBEF7365A31B0D7E3B463304FB3EBBC372A866292",
		DataRequest:  "D074C0F81866781B92D008C8EA6A3947319B94361C7ECD3C1736020E0D57E629",
		DataResponse: "08A3D4FB24E9CA4864F63E1AB518C69327D87A6A709B9336E3E60FA7F312759A",
	},
	{
		Ksn:          "123456789012345600000005",
		CurrentKey:   "C2A7AC328A5DA2D6002D62465BFC028B",
		CMACRequest:  "C0CE6DA1F4434AD16EEEBF486C9616CD",
		CMACResponse: "4B508F51104D184A9190061ED854200E",
		HMACRequest:  "E49D95FD38DF4E39371FD6FD0789E1A2E9A663E20764BF935B457ECEEAE46CBD",
		HMACResponse: "401CBB584E48C3E08A212A3117E087520D38E4EC054749747D1435B421C9DCE6",
		DataRequest:  "8F222D79AE7F942BF74D3EA9E364C0000D0C94AD7EA0A8CCF23330FCA4B1D0D0",
		DataResponse: "400E67A22795467C145D7A5D2475DFD8041C233C6E2D004CEDBEBA25AE5CE1A7",
	},
	{
		Ksn:          "123456789012345600000006",
		CurrentKey:   "D30F7D9351DA58448A2F5E92B4EE3B7D",
		CMACRequest:  "05222AE91471C590B3A9471523324C14",
		CMACResponse: "ED90BD8AE4571C75CF08EA3EA195ABF8",
		HMACRequest:  "D5B61390352342D2027DFD120F32E77831B32BF34700FBA8232D80780D492766",
		HMACResponse: "6644594E7C867C2BF0FBA7F00CAF2E184823AE0D9C40FCAA6F48A3605737094D",
		DataRequest:  "19C254B0498CBD32E597D882B7D993513994EE913836E65711EA41F8D4B34728",
		DataResponse: "1524F027685DCDA7197E0DE3CB87EF83C6D61D2E483D47678C4914DEC2320B08",
	},
	{
		Ksn:          "123456789012345600000007",
		CurrentKey:   "A8253CEED9AC042C54F75D35C8352278",
		CMACRequest:  "37FA54258AAF805A44AA1273C0DF928C",
		CMACResponse: "52D6C1D3A95B1D21761E20870D9A7E8C",
		HMACRequest:  "E0A41D52B44C96D5D730BB0DC2F747E7FE5970CE58C0043C42CD3769F6CA3925",
		HMACResponse: "55F096E89E56A27438F6D01A6DCBF9D396E29EA076C3CC9823B2BB5996ED17EE",
		DataRequest:  "0710C8F0EB136629E30ADFB148562F6F80B786EC1074428B7C7511B7301EAAF0",
		DataResponse: "8CA084F21F599C7361C8F2B1565D993779C62EC3496F0113DF17B5C29EA4E404",
	},
	{
		Ksn:          "123456789012345600000008",
		CurrentKey:   "718EE6CF0B27E53D5F7AF99C4D8146A2",
		CMACRequest:  "85C7CA68F55F51E7DCAC969B8C111130",
		CMACResponse: "B45399DB90C0BA75DB4B86605758695A",
		HMACRequest:  "D7CAB17596E6D193B83E0E13CAB35A179B7296DC04A42D8145B9DF6E60A2A47F",
		HMACResponse: "32403C170DD07A7C823247DF37649D49FDE905482D1B1C6A62E03E735FA2E384",
		DataRequest:  "304EC254A7B528D9892E47F7C1315D498C0D88EA8CD71CA52D38F362721AEA67",
		DataResponse: "8CD1A54538B9DC79A5DF4544ADE8D1F1A085AC1F89AA59BFF49351A68957DE1B",
	},
}

// B.1. Sample Test Vectors for Generating AES-128 keys from AES-128 BDK
//
//	Table 4 - BDK and Associated Data for Test Vectors
func TestAES128(t *testing.T) {
	pin := "1234"
	pan := "4111111111111111"
	macData := "4012345678909D987"

	bdk := []byte{0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1}
	initialKeyID := []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56}
	expectedIK := []byte{0x12, 0x73, 0x67, 0x1E, 0xA2, 0x6A, 0xC2, 0x9A, 0xFA, 0x4D, 0x10, 0x84, 0x12, 0x76, 0x52, 0xA1}

	// Advance to first KSN
	ksn, err := pkg.GenerateNextAesKsn(append(initialKeyID, make([]byte, 4)...))
	require.NoError(t, err)

	ik, err := DerivationOfInitialKey(bdk, ksn)
	require.NoError(t, err)
	require.Len(t, ik, 16)
	require.Equal(t, expectedIK, ik)

	for index, item := range InitialSequence {
		t.Run(fmt.Sprintf("Sequence #%d KSN: %s", index+1, item.Ksn), func(t *testing.T) {

			valid := pkg.IsValidAesKsn(ksn)
			require.Equal(t, true, valid)
			require.Equal(t, item.Ksn, strings.ToUpper(pkg.HexEncode(ksn)))

			transactionKey, err := DeriveCurrentTransactionKey(ik, ksn)
			require.NoError(t, err)
			require.Equal(t, item.CurrentKey, strings.ToUpper(pkg.HexEncode(transactionKey)))

			encPinblock, err := EncryptPin(transactionKey, ksn, pin, pan, KeyAES128Type)
			require.NoError(t, err)

			decPinblock, err := DecryptPin(transactionKey, ksn, encPinblock, pan, KeyAES128Type)
			require.NoError(t, err)
			require.Equal(t, pin, decPinblock)

			genMac, err := GenerateCMAC(transactionKey, ksn, macData, KeyAES128Type, pkg.ActionRequest)
			require.NoError(t, err)
			require.Equal(t, item.CMACRequest, strings.ToUpper(pkg.HexEncode(genMac)))

			genMac, err = GenerateCMAC(transactionKey, ksn, macData, KeyAES128Type, pkg.ActionResponse)
			require.NoError(t, err)
			require.Equal(t, item.CMACResponse, strings.ToUpper(pkg.HexEncode(genMac)))

			genMac, err = GenerateHMAC(transactionKey, ksn, macData, KeyHMAC128Type, pkg.ActionRequest)
			require.NoError(t, err)
			require.Equal(t, item.HMACRequest, strings.ToUpper(pkg.HexEncode(genMac)))

			genMac, err = GenerateHMAC(transactionKey, ksn, macData, KeyHMAC128Type, pkg.ActionResponse)
			require.NoError(t, err)
			require.Equal(t, item.HMACResponse, strings.ToUpper(pkg.HexEncode(genMac)))

			encData, err := EncryptData(transactionKey, ksn, nil, macData, KeyAES128Type, pkg.ActionRequest)
			require.NoError(t, err)
			require.Equal(t, item.DataRequest, strings.ToUpper(pkg.HexEncode(encData)))

			decData, err := DecryptData(transactionKey, ksn, encData, nil, KeyAES128Type, pkg.ActionRequest)
			require.NoError(t, err)
			require.Len(t, decData, 32)
			require.Equal(t, macData, decData[:len(macData)])

			encData, err = EncryptData(transactionKey, ksn, nil, macData, KeyAES128Type, pkg.ActionResponse)
			require.NoError(t, err)
			require.Equal(t, item.DataResponse, strings.ToUpper(pkg.HexEncode(encData)))

			decData, err = DecryptData(transactionKey, ksn, encData, nil, KeyAES128Type, pkg.ActionResponse)
			require.NoError(t, err)
			require.Len(t, decData, 32)
			require.Equal(t, macData, decData[:len(macData)])

			// next KSN
			ksn, err = pkg.GenerateNextAesKsn(ksn)
			require.NoError(t, err)
		})
	}
}
