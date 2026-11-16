package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// postJSON sends body to path and decodes the JSON response into a map.
func postJSON(t *testing.T, router http.Handler, path string, body any) (int, map[string]any) {
	t.Helper()
	requestBody, err := json.Marshal(body)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader(requestBody)))

	out := map[string]any{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out), "body: %s", w.Body.String())
	return w.Code, out
}

// createTestMachine creates a machine and advances it to its first KSN, so it
// has a transaction key, and returns its Initial Key.
func createTestMachine(t *testing.T, router http.Handler, key BaseKey) string {
	t.Helper()
	code, created := postJSON(t, router, "/machine", key)
	require.Equal(t, http.StatusOK, code, "%v", created)
	ik, ok := created["ik"].(string)
	require.True(t, ok)
	require.NotEmpty(t, ik)
	return ik
}

func TestHandlers_RoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  BaseKey
	}{
		{"des", mockBaseDesKey()},
		{"aes", mockBaseAesKey()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router := mockHttpHandler()
			ik := createTestMachine(t, router, tc.key)

			t.Run("data", func(t *testing.T) {
				plaintext := "4012345678909D987"
				for _, action := range []string{"request", "response"} {
					code, enc := postJSON(t, router, "/encrypt_data/"+ik, map[string]string{"Action": action, "Data": plaintext})
					require.Equal(t, http.StatusOK, code, "%v", enc)
					encrypted, ok := enc["encrypted"].(string)
					require.True(t, ok)
					require.NotEmpty(t, encrypted)

					code, dec := postJSON(t, router, "/decrypt_data/"+ik, map[string]string{"Action": action, "Data": encrypted})
					require.Equal(t, http.StatusOK, code, "%v", dec)
					decrypted, ok := dec["data"].(string)
					require.True(t, ok)
					// The data is zero-padded to a whole number of blocks before
					// encryption, and the padding comes back with it.
					require.Equal(t, plaintext, strings.TrimRight(decrypted, "\x00"), "action %s", action)
				}
			})

			t.Run("pin", func(t *testing.T) {
				pin, pan := "1234", "4111111111111111"
				code, enc := postJSON(t, router, "/encrypt_pin/"+ik, map[string]string{"Pin": pin, "Pan": pan})
				require.Equal(t, http.StatusOK, code, "%v", enc)
				encrypted, ok := enc["encrypted"].(string)
				require.True(t, ok)
				require.NotEmpty(t, encrypted)

				code, dec := postJSON(t, router, "/decrypt_pin/"+ik, map[string]string{"Encrypted": encrypted, "Pan": pan})
				require.Equal(t, http.StatusOK, code, "%v", dec)
				require.Equal(t, pin, dec["decrypted"])
			})
		})
	}
}

// A failed operation is reported with an error status and its message, not
// as an empty object under 200.
func TestHandlers_ReportErrors(t *testing.T) {
	router := mockHttpHandler()

	code, out := postJSON(t, router, "/encrypt_data/00112233445566778899AABBCCDDEEFF", map[string]string{"Data": "x"})
	require.NotEqual(t, http.StatusOK, code)
	msg, ok := out["error"].(string)
	require.True(t, ok, "error should be a message: %v", out)
	require.Contains(t, msg, "encrypt data")
}
