package des

import (
	"bytes"
	"testing"

	"github.com/moov-io/dukpt/encryption"
	"github.com/moov-io/dukpt/pkg"
	"github.com/moov-io/pinblock/formats"
	"github.com/stretchr/testify/require"
)

// wipeRecorder replaces the package's wipe hook for one test. It records what
// each buffer held just before it was cleared, and the buffer itself, so a test
// can check both that a given key was cleared and that the clear took effect.
type wipeRecorder struct {
	before  [][]byte
	buffers [][]byte
}

func recordWipes(t *testing.T) *wipeRecorder {
	t.Helper()
	r := &wipeRecorder{}
	original := wipe
	wipe = func(b []byte) {
		r.before = append(r.before, bytes.Clone(b))
		r.buffers = append(r.buffers, b)
		original(b)
	}
	t.Cleanup(func() { wipe = original })
	return r
}

// count returns how many cleared buffers held exactly value.
func (r *wipeRecorder) count(value []byte) int {
	n := 0
	for _, b := range r.before {
		if bytes.Equal(b, value) {
			n++
		}
	}
	return n
}

// requireWiped fails unless some cleared buffer held exactly value.
func (r *wipeRecorder) requireWiped(t *testing.T, value []byte, name string) {
	t.Helper()
	require.Positive(t, r.count(value), "%s (%X) was never passed to wipe", name, value)
}

// requireAllZero fails unless every buffer passed to wipe is still all zero
// when the function under test has returned.
func (r *wipeRecorder) requireAllZero(t *testing.T) {
	t.Helper()
	require.NotEmpty(t, r.buffers)
	for i, b := range r.buffers {
		require.Equal(t, make([]byte, len(b)), b, "buffer %d is not zero after return", i)
	}
}

// variant returns key with the given bytes inverted (ANSI X9.24-1:2009 A.4.1,
// table A-1).
func variant(key []byte, positions ...int) []byte {
	v := bytes.Clone(key)
	for _, p := range positions {
		v[p] ^= 0xFF
	}
	return v
}

var (
	wipeTestBDK = pkg.HexDecode("0123456789ABCDEFFEDCBA9876543210")
	wipeTestIK  = pkg.HexDecode("6AC292FAA1315B4D858AB3A3D7D5933A")
	// Counter 3 has two bits set: one intermediate key, then the result.
	wipeTestKSN = pkg.HexDecode("FFFF9876543210E00003")
	wipeTestTK  = pkg.HexDecode("0DF3D9422ACA56E547676D07AD6BADFA")
)

func TestDerivationOfInitialKey_ClearsVariantAndHalves(t *testing.T) {
	bdkVariant := bytes.Clone(wipeTestBDK)
	serializeKeyWithHexadecimal(bdkVariant)

	r := recordWipes(t)
	bdk := bytes.Clone(wipeTestBDK)

	ik, err := DerivationOfInitialKey(bdk, wipeTestKSN)
	require.NoError(t, err)
	require.Equal(t, wipeTestIK, ik)
	require.Equal(t, wipeTestBDK, bdk, "bdk must not be modified")

	r.requireWiped(t, bdkVariant, "BDK variant")
	r.requireWiped(t, wipeTestIK[:8], "left half")
	r.requireWiped(t, wipeTestIK[8:], "right half")
	r.requireAllZero(t)
}

func TestMakeNonReversibleKey_ClearsRegisters(t *testing.T) {
	ksnReg := serializeKeySerialNumber(wipeTestKSN)
	keyReg := bytes.Clone(wipeTestIK)

	r := recordWipes(t)
	next, err := makeNonReversibleKey(ksnReg, keyReg)
	require.NoError(t, err)

	// Each register is cleared once when its encrypted value replaces it, and
	// once more on return, by which time it holds its half of the result.
	require.Len(t, r.buffers, 4)
	r.requireWiped(t, next[:8], "crypto register 1")
	r.requireWiped(t, next[8:], "crypto register 2")
	r.requireAllZero(t)
}

func TestDeriveCurrentTransactionKey_ClearsIntermediates(t *testing.T) {
	// The one intermediate key, for counter bit 2 alone.
	ksnReg := serializeKeySerialNumber(wipeTestKSN)
	removeTransactionCounter(ksnReg)
	ksnReg[keySerialLen-1] |= 0x02
	intermediate, err := makeNonReversibleKey(ksnReg, bytes.Clone(wipeTestIK))
	require.NoError(t, err)

	r := recordWipes(t)
	ik := bytes.Clone(wipeTestIK)

	key, err := DeriveCurrentTransactionKey(ik, wipeTestKSN)
	require.NoError(t, err)
	require.Equal(t, wipeTestTK, key)
	require.Equal(t, wipeTestIK, ik, "ik must not be modified")

	r.requireWiped(t, intermediate, "intermediate key")
	// The last step's output, and the Key Register holding the same value, are
	// both cleared; only the returned copy remains.
	require.Equal(t, 2, r.count(wipeTestTK), "final key register and last step output")
	r.requireAllZero(t)
}

func TestWorkingKeys_AreCleared(t *testing.T) {
	pin, pan := "1234", "4012345678909"
	message := "4012345678909D987"

	clearPinBlock := func() []byte {
		f, err := formats.NewFormatter("ISO-0")
		require.NoError(t, err)
		block, err := f.Encode(pin, pan)
		require.NoError(t, err)
		return pkg.HexDecode(block)
	}()

	// The TDEA data key is the data variant encrypted under itself, in halves.
	dataKeys := func(v []byte) (left, right, full []byte) {
		c, err := encryption.NewTripleDesECB(v)
		require.NoError(t, err)
		left, err = c.Encrypt(v[:8])
		require.NoError(t, err)
		right, err = c.Encrypt(v[8:])
		require.NoError(t, err)
		return left, right, append(bytes.Clone(left), right...)
	}

	encryptedPin, err := EncryptPin(wipeTestTK, pin, pan, "ISO-0")
	require.NoError(t, err)
	encrypted, err := EncryptData(wipeTestTK, nil, message, pkg.ActionRequest)
	require.NoError(t, err)

	reqData := variant(wipeTestTK, 5, 13)
	reqLeft, reqRight, reqFull := dataKeys(reqData)
	padded := make([]byte, 24)
	copy(padded, message)

	cases := []struct {
		name string
		want map[string][]byte
		call func() error
	}{
		{"EncryptPin", map[string][]byte{
			"PIN key variant": variant(wipeTestTK, 7, 15),
			"clear PIN block": clearPinBlock,
		}, func() error {
			_, err := EncryptPin(wipeTestTK, pin, pan, "ISO-0")
			return err
		}},
		{"DecryptPin", map[string][]byte{
			"PIN key variant": variant(wipeTestTK, 7, 15),
			"clear PIN block": clearPinBlock,
		}, func() error {
			_, err := DecryptPin(wipeTestTK, encryptedPin, pan, "ISO-0")
			return err
		}},
		{"GenerateMac request", map[string][]byte{
			"MAC key variant": variant(wipeTestTK, 6, 14),
			"padded message":  padded,
		}, func() error {
			_, err := GenerateMac(wipeTestTK, message, pkg.ActionRequest)
			return err
		}},
		{"GenerateMac response", map[string][]byte{
			"MAC key variant": variant(wipeTestTK, 4, 12),
			"padded message":  padded,
		}, func() error {
			_, err := GenerateMac(wipeTestTK, message, pkg.ActionResponse)
			return err
		}},
		{"EncryptData", map[string][]byte{
			"data key variant": reqData,
			"data key left":    reqLeft,
			"data key right":   reqRight,
			"data key":         reqFull,
			"padded plaintext": padded,
		}, func() error {
			_, err := EncryptData(wipeTestTK, nil, message, pkg.ActionRequest)
			return err
		}},
		{"DecryptData", map[string][]byte{
			"data key variant": reqData,
			"data key left":    reqLeft,
			"data key right":   reqRight,
			"data key":         reqFull,
			"decrypted bytes":  padded,
		}, func() error {
			_, err := DecryptData(wipeTestTK, encrypted, nil, pkg.ActionRequest)
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := recordWipes(t)
			before := bytes.Clone(wipeTestTK)
			require.NoError(t, c.call())
			for name, value := range c.want {
				r.requireWiped(t, value, name)
			}
			r.requireAllZero(t)
			require.Equal(t, before, wipeTestTK, "the transaction key must not be modified")
		})
	}
}

func TestDecryptData_ResultSurvivesClear(t *testing.T) {
	plaintext := "4012345678909D987"
	padded := make([]byte, 24)
	copy(padded, plaintext)

	encrypted, err := EncryptData(wipeTestTK, nil, plaintext, pkg.ActionRequest)
	require.NoError(t, err)

	// The decrypted bytes are cleared before DecryptData returns, so the
	// returned string must have been copied from them first.
	r := recordWipes(t)
	decrypted, err := DecryptData(wipeTestTK, encrypted, nil, pkg.ActionRequest)
	require.NoError(t, err)
	r.requireWiped(t, padded, "decrypted bytes")
	require.Equal(t, string(padded), decrypted)
}
