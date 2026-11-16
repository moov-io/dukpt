package aes

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/moov-io/dukpt/v2/encryption"
	"github.com/moov-io/dukpt/v2/pkg"
	"github.com/stretchr/testify/require"
)

// AES-192 vectors. ANSI X9.24-3-2017 Annex B prints vectors for AES-128 only
// and refers to a separately distributed set for the other key sizes. These
// were computed from the standard's section 6 pseudocode (Tables 2 and 3,
// Derive_Key in 6.3.1, the transaction key loop in 6.5), with every AES
// operation (ECB, CBC and CMAC) done by the OpenSSL command-line tool, not by
// this package. The same script reproduces the Annex B.1 AES-128 values.
//
// BDK and Initial Key ID follow Annex B.1, with the BDK extended to 24 bytes.
var (
	aes192BDK = pkg.HexDecode("FEDCBA9876543210F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1")
	aes192IK  = "83C9FDE8CBF6006CE4D74F73DA8953F07823279B7FEBA5BD"
)

var aes192Sequence = []SequenceItem{
	{Ksn: "123456789012345600000001", CurrentKey: "2251A5725FC146FE7CEAB6EE5BBB2B46CA608533EC93D0D5",
		DataRequest: "3E466DEE19BB141CBE2E9B68AAB9A3AD25E3DFF916D53CF2FBB3CE6ED1C627CB", DataResponse: "604790D8EAF80E8B3B5120DEDA1F0E4DCE5D3D02029213532A89463693FB065F",
		CMACRequest: "1089E71E6D85301B00FBA51D618F6D61", CMACResponse: "52C8DE0A0B5DA9829E25E5351B486740"},
	{Ksn: "123456789012345600000002", CurrentKey: "EA04AEF92F371D90BF6502C29DEB4D601CBFBB29A8FBA7BC",
		DataRequest: "B9F4C6E879AA2ABE9C88E2DACC69B1A336D3E9A4B3A4682619C86023B7FDF031", DataResponse: "8247DDAC45EC3F3E5549BC69EC1C6ED6281E762035CD1447E559BA9FADBDB33B",
		CMACRequest: "61D8AFC91B5DA5A8054A0D854A386929", CMACResponse: "0B40E551AC7AB2A4D7A5CB67586B6772"},
	{Ksn: "123456789012345600000003", CurrentKey: "25C0FC006BE263F4D5BBF4B2D2A5C3F4A0B25584E63ADE6B",
		DataRequest: "2D76E4E103F29557586D6F59C8408405073B116F4F23A8F722C3F08592B1B57E", DataResponse: "655FB5FE30AAEFD0A015D1DA2894E08FDF9A942FA0CECD6400327EA44D71F46C",
		CMACRequest: "C42FCF9FAC9B30BA832803FC8AC8A3DC", CMACResponse: "C41C22D9A6C9380C9A9A524A59F57678"},
	{Ksn: "123456789012345600000004", CurrentKey: "0F5AA4E59D7EDD176BBD5D9D5D8502B21C3B26405BB91168",
		DataRequest: "D4FC1DB2CFA32D2C4D673FCA35B433B09AF4D87F0B7860D07A36A9A2710C962B", DataResponse: "B7C5C3716892C93D0CA1A723AC4AB4EEE232C025651DB611EE51DDD58FCA998F",
		CMACRequest: "12F27B3AD49E5D54BBBC97F0A2EC684F", CMACResponse: "DAF42B41C609DFA5F1A87E057C8B4585"},
	{Ksn: "123456789012345600000005", CurrentKey: "25CD05625A20DD1A92D428FFB8AAE0CDF05E4745DF9E90F3",
		DataRequest: "30D9BAA8D7DCB2404427333840422CAC83B0E9F23E9C9B72458C3443510ADCD9", DataResponse: "BF946103149D8749AD40432DCD9394AD6D2B6E1F1E37F39E71D0AA54BC0C0634",
		CMACRequest: "3BC43CF5F20227D3585489D5AF14A4F4", CMACResponse: "DE52F6CFBB4D1B96BC504761E4D0C1E0"},
	{Ksn: "12345678901234560000000B", CurrentKey: "797863037E53733916137DD122ED394A1153EB84147D1F8E",
		DataRequest: "B3EBD6662E9B42961F934586823DF5FB9A63248896143B8C48D3BC6FFB049774", DataResponse: "1B9F0B800AF52B67397AAECA86A934A9F065C632EEAA99E7FDA5A9A21DB549A8",
		CMACRequest: "98CA44BD9A414786ACAB2F10F4D76956", CMACResponse: "352CCF9662A6F234CB76F2EB05C4B787"},
	{Ksn: "12345678901234560001FFFE", CurrentKey: "103DF931BCB3C47A0796281284607D651E760C282E89C981",
		DataRequest: "240EA373389B58FBA4A553917FC38240724144BE0D4BD1D7B10A6CEBCCCD8F7B", DataResponse: "43FBC401F7B20A256F687D51561DE4AA47743AA8DD8D345C8A705F2865A2C2FD",
		CMACRequest: "084232D1A8072694AB8D2905FAB72549", CMACResponse: "21E4FFE7D92645E648BEAB1D58AA02F4"},
	{Ksn: "123456789012345600020000", CurrentKey: "76BF28534BB958627AD149AB096CA0C2B81A4E2AF437CFB3",
		DataRequest: "456C8C6EB0EE76BAB832310B4460CC253D4F73075768DA2CB1E50DC2FA84A65A", DataResponse: "4EE1F9D00C5F2023E0A9FF886AD8F536D559497983FC7A0696C805979D841686",
		CMACRequest: "BECFE56204A5AA54D9B316D1CB51BB7E", CMACResponse: "C0308EA327EFC08E5EC656B94915533C"},
}

func TestAES192(t *testing.T) {
	data := []byte("4012345678909D987")
	initialKeyID := pkg.HexDecode("1234567890123456")

	ik, err := DerivationOfInitialKey(aes192BDK, initialKeyID)
	require.NoError(t, err)
	require.Len(t, ik, 24)
	require.Equal(t, aes192IK, strings.ToUpper(pkg.HexEncode(ik)))

	for _, item := range aes192Sequence {
		t.Run(fmt.Sprintf("KSN %s", item.Ksn), func(t *testing.T) {
			ksn := pkg.HexDecode(item.Ksn)

			tk, err := DeriveCurrentTransactionKey(ik, ksn)
			require.NoError(t, err)
			require.Len(t, tk, 24)
			require.Equal(t, item.CurrentKey, strings.ToUpper(pkg.HexEncode(tk)))

			for _, c := range []struct {
				action, data, cmac string
			}{
				{pkg.ActionRequest, item.DataRequest, item.CMACRequest},
				{pkg.ActionResponse, item.DataResponse, item.CMACResponse},
			} {
				encrypted, err := EncryptData(tk, ksn, nil, data, KeyAES192Type, c.action)
				require.NoError(t, err)
				require.Equal(t, c.data, strings.ToUpper(pkg.HexEncode(encrypted)), c.action)

				decrypted, err := DecryptData(tk, ksn, encrypted, nil, KeyAES192Type, c.action)
				require.NoError(t, err)
				require.Equal(t, data, decrypted[:len(data)], c.action)

				mac, err := GenerateCMAC(tk, ksn, data, KeyAES192Type, c.action)
				require.NoError(t, err)
				require.Equal(t, c.cmac, strings.ToUpper(pkg.HexEncode(mac)), c.action)
			}

			encryptedPin, err := EncryptPin(tk, ksn, "1234", "4111111111111111", KeyAES192Type)
			require.NoError(t, err)
			pin, err := DecryptPin(tk, ksn, encryptedPin, "4111111111111111", KeyAES192Type)
			require.NoError(t, err)
			require.Equal(t, "1234", pin)
		})
	}
}

// Every derived key is exactly its type's length, so key lengths are preserved
// along the derivation chain and match the key type passed to the working-key
// functions.
func TestDerivedKeyLengths(t *testing.T) {
	for _, tc := range []struct {
		keyType string
		length  int
	}{
		{KeyAES128Type, 16}, {KeyAES192Type, 24}, {KeyAES256Type, 32},
		{KeyHMAC128Type, 16}, {KeyHMAC192Type, 24}, {KeyHMAC256Type, 32},
	} {
		data, err := createDerivationData(usageForMessageGeneration, tc.keyType, pkg.HexDecode("123456789012345600000001"), 1)
		require.NoError(t, err)
		key, err := derivationKey(bytes.Repeat([]byte{0x11}, 32), data)
		require.NoError(t, err)
		require.Len(t, key, tc.length, tc.keyType)
		require.Equal(t, tc.length, cap(key), "%s: the result must not reach past the key", tc.keyType)
	}
}

// The unused half of the second block of a 192-bit derivation is cleared.
func TestDerivationKey_ClearsTruncatedTail(t *testing.T) {
	data, err := createDerivationData(usageForKeyInitialKey, KeyAES192Type, pkg.HexDecode("1234567890123456"), 0)
	require.NoError(t, err)
	data.KeyBlockCounter = 2
	cipher, err := encryption.NewAesECB(aes192BDK)
	require.NoError(t, err)
	secondBlock, err := cipher.Encrypt(data.Bytes())
	require.NoError(t, err)

	r := recordWipes(t)
	ik, err := DerivationOfInitialKey(aes192BDK, pkg.HexDecode("1234567890123456"))
	require.NoError(t, err)
	require.Equal(t, secondBlock[:8], ik[16:])

	r.requireWiped(t, secondBlock[8:], "truncated tail of the second block")
	r.requireAllZero(t)
}
