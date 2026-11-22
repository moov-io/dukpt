[![Moov Banner Logo](https://user-images.githubusercontent.com/20115216/104214617-885b3c80-53ec-11eb-8ce0-9fc745fb5bfc.png)](https://github.com/moov-io)

<p align="center">
  <a href="https://pkg.go.dev/github.com/moov-io/dukpt">Project Documentation</a>
  ·
  <a href="#rest-apis">API Endpoints</a>
  ·
  <a href="https://slack.moov.io/">Community</a>
  ·
  <a href="https://moov.io/blog/">Blog</a>
  <br>
  <br>
</p>


# moov-io/dukpt
This project implements the ANSI X9.24-3:2017 standard for TDES and AES Derived Unique Key Per Transaction (DUKPT) key management. Since most uses of this standard involve dedicated security hardware, this implementation is mostly for validation and debugging. 

## Table of contents

- [Project status](#project-status)
- [Usage](#usage)
    - [Go library](#go-library)
    - [DUKPT apis](#dukpt-apis)
    - [How to](#how-to)
    - [What the caller must do](#what-the-caller-must-do)
    - [Command lines](#command-lines)
    - [Service Instance](#service-instance)
    - [Rest APIs](#rest-apis)
        - [Run the server](#run-the-server)
        - [Examples](#examples)
- [Supported and tested platforms](#supported-and-tested-platforms)
- [Contributing](#contributing)
- [Releasing](#releasing)
- [Testing](#testing)
- [Related projects](#related-projects)
- [License](#license)

## Project status

Moov dukpt is actively used for validation and debugging. Please star the project if you are interested in its progress. If you have layers above dukpt to simplify tasks, perform business operations, or found bugs we would appreciate an issue or pull request. Thanks!

## Usage

### Go library

This project uses [Go Modules](https://go.dev/blog/using-go-modules) and Go v1.26 or newer. See [Golang's install instructions](https://golang.org/doc/install) for help setting up Go. You can download the source code and we offer [tagged and released versions](https://github.com/moov-io/dukpt/releases/latest) as well. We highly recommend you use a tagged release for production.

Add the library to your module. Run `go mod tidy` after you add the imports (for example `github.com/moov-io/dukpt/pkg/des` or `github.com/moov-io/dukpt/pkg/aes`) to your code, so that `go.sum` gets the entries for their dependencies.

```
$ go get github.com/moov-io/dukpt@latest
$ go mod tidy
```

Releases have no binaries and there is no Docker image. Install the CLI with Go:

```
$ go install github.com/moov-io/dukpt/cmd/dukptcli@latest
```

To build from source:

```
$ git clone https://github.com/moov-io/dukpt.git
$ cd dukpt
$ go build ./...
$ go run ./cmd/dukptcli -h
$ go run ./cmd/server
```

### DUKPT apis

Moov dukpt project supported general utility functions for managing transaction key. The functions divided into two group as aes and des

- Functions for triple data encryption algorithm (des)
```
    func DerivationOfInitialKey(bdk, ksn []byte) ([]byte, error)
    func DeriveCurrentTransactionKey(ik, ksn []byte) ([]byte, error)
    func EncryptPin(currentKey []byte, pin, pan string, format string) ([]byte, error)
    func DecryptPin(currentKey, ciphertext []byte, pan string, format string) (string, error)
    func GenerateMac(currentKey []byte, plainText, action string) ([]byte, error)
    func EncryptData(currentKey, iv []byte, plainText, action string) ([]byte, error)
    func DecryptData(currentKey, ciphertext, iv []byte, action string) (string, error)
```

- Functions for advanced encryption standard (aes)
```
    func DerivationOfInitialKey(bdk, kid []byte) ([]byte, error)
    func DeriveCurrentTransactionKey(ik, ksn []byte) ([]byte, error)
    func EncryptPin(currentKey, ksn []byte, pin, pan string, keyType string) ([]byte, error)
    func DecryptPin(currentKey, ksn, ciphertext []byte, pan string, keyType string) (string, error)
    func GenerateCMAC(currentKey, ksn []byte, plaintext string, keyType string, action string) ([]byte, error)
    func GenerateHMAC(currentKey, ksn []byte, plaintext string, keyType string, action string) ([]byte, error)
    func EncryptData(currentKey, ksn, iv []byte, plaintext, keyType, action string) ([]byte, error)
    func DecryptData(currentKey, ksn, ciphertext, iv []byte, keyType, action string) (string, error)
```

- Utility functions in `github.com/moov-io/dukpt/pkg`
```
    func GenerateNextAesKsn(ksn []byte) ([]byte, error)  // next AES key serial number
    func GenerateNextDesKsn(ksn []byte) ([]byte, error)  // next TDES key serial number
    func GetAesTcFromKsn(ksn []byte) uint32              // transaction counter of an AES key serial number
    func GetDesTcFromKsn(ksn []byte) uint32              // transaction counter of a TDES key serial number
    func IsValidAesKsn(ksn []byte) bool                  // checks an AES key serial number before you derive keys
    func HexDecode(data string) []byte                   // returns nil if data is not valid hex
    func HexEncode(data []byte) string
```

- `func Clear(b []byte)` in `github.com/moov-io/dukpt` clears a key that you no longer need.

### How to

First step is to derive initial key from base derivative key (BDK) and key serial number (KSN). For aes, `DerivationOfInitialKey` uses only the first 8 bytes of the KSN (the initial key ID), so you can give the initial key ID or the full 12-byte KSN. The package doesn't specify how to get the base derivative key.

Second step is to derive the transaction key from the initial key and the key serial number. Then use the transaction key to encrypt and decrypt data (PIN, MAC, normal data).

The program below uses the ANSI X9.24-1 (des) and ANSI X9.24-3 (aes) test vectors. It is in [example_test.go](example_test.go), and `go test` runs it.

```go
package main

import (
	"fmt"
	"log"

	"github.com/moov-io/dukpt"
	"github.com/moov-io/dukpt/pkg"
	"github.com/moov-io/dukpt/pkg/aes"
	"github.com/moov-io/dukpt/pkg/des"
)

func main() {
	// des
	bdk := pkg.HexDecode("0123456789ABCDEFFEDCBA9876543210")
	ksn := pkg.HexDecode("FFFF9876543210E00001")

	ik, err := des.DerivationOfInitialKey(bdk, ksn)
	if err != nil {
		log.Fatal(err)
	}
	defer dukpt.Clear(ik)

	transactionKey, err := des.DeriveCurrentTransactionKey(ik, ksn)
	if err != nil {
		log.Fatal(err)
	}
	defer dukpt.Clear(transactionKey)

	encryptedPin, err := des.EncryptPin(transactionKey, "1234", "4012345678909", "ISO-0")
	if err != nil {
		log.Fatal(err)
	}
	decryptedPin, err := des.DecryptPin(transactionKey, encryptedPin, "4012345678909", "ISO-0")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(pkg.HexEncode(ik), pkg.HexEncode(encryptedPin), decryptedPin)
	// 6ac292faa1315b4d858ab3a3d7d5933a 1b9c1845eb993a7a 1234

	// aes
	aesBdk := pkg.HexDecode("FEDCBA9876543210F1F1F1F1F1F1F1F1")
	aesKsn := pkg.HexDecode("123456789012345600000001")
	if !pkg.IsValidAesKsn(aesKsn) {
		log.Fatal("invalid KSN")
	}

	aesIk, err := aes.DerivationOfInitialKey(aesBdk, aesKsn)
	if err != nil {
		log.Fatal(err)
	}
	defer dukpt.Clear(aesIk)

	aesTransactionKey, err := aes.DeriveCurrentTransactionKey(aesIk, aesKsn)
	if err != nil {
		log.Fatal(err)
	}
	defer dukpt.Clear(aesTransactionKey)

	encPinblock, err := aes.EncryptPin(aesTransactionKey, aesKsn, "1234", "4111111111111111", aes.KeyAES128Type)
	if err != nil {
		log.Fatal(err)
	}
	decPinblock, err := aes.DecryptPin(aesTransactionKey, aesKsn, encPinblock, "4111111111111111", aes.KeyAES128Type)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(pkg.HexEncode(aesIk), pkg.HexEncode(aesTransactionKey), decPinblock)
	// 1273671ea26ac29afa4d1084127652a1 4f21b565bad9835e112b6465635eae44 1234
}
```

Notes:

- The des PIN block formats are strings such as `"ISO-0"`, `"ISO-1"`, `"ISO-3"` and `"ANSI"` (see [moov-io/pinblock](https://github.com/moov-io/pinblock)). The aes `EncryptPin` uses ISO-4.
- The aes key types are `aes.KeyAES128Type`, `aes.KeyAES192Type`, `aes.KeyAES256Type` and, for `GenerateHMAC`, `aes.KeyHMAC128Type`, `aes.KeyHMAC192Type`, `aes.KeyHMAC256Type`.
- The action of the MAC and data functions is `pkg.ActionRequest` (`"request"`) or `pkg.ActionResponse` (`"response"`).
- `DecryptData` returns the data with its zero padding. For example, `"hello"` encrypted with aes comes back as `"hello"` followed by 11 zero bytes.

### What the caller must do

The library derives and uses keys; it keeps no state. ANSI X9.24-3 puts the following
on the system that uses it, and getting them wrong breaks DUKPT's security without any
error from this package.

- **Issue each Initial Key ID once.** An AES Initial Key ID is 8 bytes: a 4-byte BDK ID
  followed by a 4-byte Derivation ID (X9.24-3 §5.1). The initial key depends only on the
  BDK and this ID, so issuing the same ID twice issues the same initial key, and the second
  device's transaction counter starts over, repeating transaction keys the first device
  already used. Do not compute the ID from something stable such as a device serial
  number or a terminal ID: re-provisioning that device would hand it the same key again.
  Draw a fresh Derivation ID for every initial key and record every ID ever issued under a
  BDK, so none is reused.
- **Validate the KSN before deriving.** A transaction counter of zero names no transaction
  key: `DeriveCurrentTransactionKey` applies one derivation step per set counter bit, so
  with no bits set the "transaction key" is the initial key itself. A counter with more than
  16 bits set (AES) is one a conforming device never produces. Check
  `pkg.IsValidAesKsn(ksn)` before deriving from a KSN you received.
- **Reject replayed counters on the host.** Each counter selects a transaction key meant
  to be used once, and a device advances its counter for every transaction. X9.24-3 says
  the receiving system should reject a counter at or below one it has already processed
  for the same Initial Key ID. Keep the highest counter accepted per Initial Key ID, and
  update it atomically.
- **Check what you decrypt.** `DecryptData` is AES-CBC and authenticates nothing: under
  the wrong key it still returns bytes, not an error. Check the plaintext's format (or a
  MAC) before trusting it.
- **Keep the previous KSN if you need it.** In v1.0.0, `GenerateNextAesKsn` and
  `GenerateNextDesKsn` write the new counter into the slice passed in, so copy the KSN
  before you call them. From v1.1.0, they do not change the slice passed in; they return
  a new slice.
- **Clear the keys you hold.** Every key the library returns (initial key, transaction
  key) belongs to the caller, who should clear it with `dukpt.Clear(key)` as soon as it is
  no longer needed. Prefer it to the `clear` builtin: a `clear` with no later read is a
  dead store the compiler may remove, while `dukpt.Clear` always writes. The library
  clears its own intermediates: each derivation step's key, the working keys for PIN, MAC
  and data encryption, and its byte copies of data (padded plaintext, the buffer data is
  decrypted into). It cannot clear the key schedules held inside `crypto/aes`,
  `crypto/des`, `crypto/hmac` and the CMAC implementation, nor any string: a PIN, a PAN,
  data passed to or returned by the MAC and data functions, or a key in hex. In
  particular the result of `DecryptData` is a string, so the decrypted data stays in
  memory until the garbage collector reuses it. `pkg.HexEncode` and `pkg.HexDecode`, the
  HTTP server and the CLI also handle keys in hex, so prefer the `[]byte` key functions
  when handling live keys.
- **`DerivationOfInitialKey(bdk, ksn)` uses only the first 8 bytes** of `ksn` (the Initial
  Key ID) for AES, so passing either the ID or a full 12-byte KSN gives the same key.

### Command lines

```
dukptcli is a tool for both tdes and aes derived unique key per transaction (dukpt) key management.

USAGE
   dukptcli [-v] [-algorithm] [-ik] [-tk] [-ep] [-dp] [-gm] [-en] [-de]

EXAMPLES
  dukptcli -v          Print the version of dukptcli (Example: v1.2.0)
  dukptcli -algorithm  Data encryption algorithm (options: des, aes)
  dukptcli -ik         Derive initial key from base derivative key and key serial number
  dukptcli -tk         Derive transaction key (current transaction key) from initial key and key serial number
  dukptcli -ep         Encrypt pin block using dukpt transaction key
  dukptcli -dp         Decrypt pin block using dukpt transaction key
  dukptcli -gm         Generate mac using dukpt transaction key
  dukptcli -en         Encrypt data using dukpt transaction key
  dukptcli -de         Decrypt data using dukpt transaction key

FLAGS
  -algorithm string
    	data encryption algorithm (options: des, aes) (default "des")
  -algorithm.key_type string
    	key type of aes, not case sensitive (options: AES128, AES192, AES256, HMAC128, HMAC192, HMAC256). With gm.type=hmac, AES<n> is used as HMAC<n> (default "AES128")
  -de
    	decrypt data using dukpt transaction key
  -de.action string
    	request or response action (default "request")
  -de.data string
    	encrypted text transformed from plaintext using an encryption algorithm
  -de.iv string
    	initial vector (not formatted string)
  -de.ksn string
    	key serial number
  -de.tk string
    	current transaction key
  -dp
    	decrypt pin block using dukpt transaction key
  -dp.format string
    	pin block format (ISO-0, ISO-1, ISO-2, ISO-3, ISO-4, ANSI, ECI1, ECI2, ECI3, ECI4, VISA1, VISA2, VISA3, VISA4)
  -dp.ksn string
    	key serial number
  -dp.pan string
    	not formatted pan string
  -dp.pin string
    	encrypted text transformed from plaintext using an encryption algorithm
  -dp.tk string
    	current transaction key
  -en
    	encrypt data using dukpt transaction key
  -en.action string
    	request or response action (default "request")
  -en.data string
    	not formatted request data
  -en.iv string
    	initial vector (not formatted string)
  -en.ksn string
    	key serial number
  -en.tk string
    	current transaction key
  -ep
    	encrypt pin block using dukpt transaction key
  -ep.format string
    	pin block format (ISO-0, ISO-1, ISO-2, ISO-3, ISO-4, ANSI, ECI1, ECI2, ECI3, ECI4, VISA1, VISA2, VISA3, VISA4)
  -ep.ksn string
    	key serial number
  -ep.pan string
    	not formatted pan string
  -ep.pin string
    	not formatted pin string
  -ep.tk string
    	current transaction key
  -gm
    	generate mac using dukpt transaction key
  -gm.action string
    	request or response action (default "request")
  -gm.data string
    	not formatted request data
  -gm.ksn string
    	key serial number
  -gm.tk string
    	current transaction key
  -gm.type string
    	cmac or hmac style (is valid using aes algorithm) (default "cmac")
  -ik
    	derive initial key from base derivative key and key serial number
  -ik.bdk string
    	base derivative key
  -ik.ksn string
    	key serial number (des: 10 bytes, aes: 12 bytes, which includes the initial key id)
  -tk
    	derive transaction key (current transaction key) from initial key and key serial number
  -tk.ik string
    	initial key
  -tk.ksn string
    	key serial number
  -v	Print dupkt cli version
```

User should use main flag and sub flag. algorithm.key_type flag is a sub flag of algorithm flag.

The values of `-algorithm`, `-algorithm.key_type` and `-gm.type` are not case sensitive. With `-algorithm=aes`, the key type is `AES128` by default. Use `AES192` or `AES256` for longer keys. With `-gm.type=hmac`, the key type `AES<n>` is used as `HMAC<n>`.

`-ik.ksn` takes the key serial number for both algorithms: 10 bytes for TDES, and 12 bytes for AES. The AES key serial number includes the 8-byte initial key id.

Values such as keys, key serial numbers and encrypted text are hex. A value that is not valid hex gives an error that names the flag value, for example `invalid hex value for bdk`.

There are some execution flags in this cli
```
    dukptcli -ik         Derive initial key from base derivative key and key serial number
    dukptcli -tk         Derive transaction key (current transaction key) from initial key and key serial number
    dukptcli -ep         Encrypt pin block using dukpt transaction key
    dukptcli -dp         Decrypt pin block using dukpt transaction key
    dukptcli -gm         Generate mac using dukpt transaction key
    dukptcli -en         Encrypt data using dukpt transaction key
    dukptcli -de         Decrypt data using dukpt transaction key
```
Execution flags (ik, tk, ep, dp, gm, en, de) can use with algorithm. These flags can't run simultaneously. 
That is that will do a main execution only.
Execution priority is ik, tk, ep, dp, gm, en, de when setting several main flags.

Example:
```
    dukptcli -algorithm=des  -gm=true  -ik=true -ik.bdk=0123456789ABCDEFFEDCBA9876543210 -ik.ksn=FFFF9876543210E00001
    RESULT: 6ac292faa1315b4d858ab3a3d7d5933a
```
In above example, the execution is to derive initial key with specified algorithm although set two execution flags

### Service instance
DUKPT library provided service instance that support multi dukpt encrypt machines. 

The service and its REST API are a **test simulator**, not production key management. It
looks machines up by their initial key, a secret, which appears in the REST paths
(`/machine/{ik}`); the in-memory repository holds the BDK, initial key and transaction key
in plain text; and it does none of the checks in [What the caller must
do](#what-the-caller-must-do). Use it to generate test vectors or exercise a device, not to
hold real keys.
```
type Service interface {
	CreateMachine(m *Machine) error
	GetMachine(ik string) (*Machine, error)
	GetMachines() []*Machine
	MakeNextKSN(ik string) (*Machine, error)
	DeleteMachine(ik string) error
	EncryptPin(ik, pin, pan, format string) (string, error)
	DecryptPin(ik, ciphertext, pan, format string) (string, error)
	GenerateMac(ik, data, action, macType string) (string, error)
	EncryptData(ik, data, action, iv string) (string, error)
	DecryptData(ik, ciphertext, action, iv string) (string, error)
}
```

User can use the service instance using special logger
```
	logger := log.NewLogger(kitlogger)
	logger.Logf("Starting dukpt server version %s", dukpt.Version)

	// Setup underlying dukpt service
	r := server.NewRepositoryInMemory(logger)
	svc = server.NewService(r)
```

### Rest APIs
DUKPT library provided web server. Please check following http endpoints

| Method | Request Body | Route              | Action         |
|--------|--------------|--------------------|----------------|
| GET    |              | /ping              | Health check   |
| GET    |              | /machines          | Get Machines   |
| GET    |              | /machine/{ik}      | Get Machine    |
| POST   | JSON         | /machine           | Create Machine |
| POST   |              | /generate_ksn/{ik} | Generate KSN   |
| POST   | JSON         | /encrypt_pin/{ik}  | Encrypt PIN    |
| POST   | JSON         | /decrypt_pin/{ik}  | Decrypt Pin    |
| POST   | JSON         | /generate_mac/{ik} | Generate Mac   |
| POST   | JSON         | /encrypt_data/{ik} | Encrypt Data   |
| POST   | JSON         | /decrypt_data/{ik} | Decrypt Data   |

`{ik}` is the initial key of the machine, in hex. There is no route to delete a machine. The server keeps machines in memory, so they are lost when it stops.

User can create web service using following http handler 
```
	handler = server.MakeHTTPHandler(svc)
```

#### Run the server

Run the server from a clone of this repository:

```
$ go run ./cmd/server
ts=... msg="Starting dukpt server version v1.2.0" level=info
ts=... msg="startup binding to :8095 for HTTP server" level=info
ts=... msg="admin listening on [::]:9105" level=info
```

The HTTP server listens on `:8095` and the admin server (`/version`, metrics) listens on `:9105`. To change the addresses, use the `-http.addr` and `-admin.addr` flags or the `HTTP_BIND_ADDRESS` and `HTTP_ADMIN_BIND_ADDRESS` environment variables:

```
$ go run ./cmd/server -http.addr :8099 -admin.addr :9109
```

#### Examples

The examples use the des and aes test vectors from [How to](#how-to). All values are hex strings, and the field names are case-sensitive. An error response has an `error` field, for example `{"error":"not found"}` with status 404 for an unknown `{ik}`.

```
$ curl localhost:8095/ping
PONG
```

Create a des machine. `AlgorithmKey` is empty for des.

```
$ curl -XPOST localhost:8095/machine -d '{"Algorithm":"des","AlgorithmKey":"","BaseDerivativeKey":"0123456789ABCDEFFEDCBA9876543210","KeySerialNumber":"FFFF9876543210E00001"}'
{"ik":"6ac292faa1315b4d858ab3a3d7d5933a","machine":{"Algorithm":"des","AlgorithmKey":"","BaseDerivativeKey":"0123456789ABCDEFFEDCBA9876543210","KeySerialNumber":"FFFF9876543210E00001","InitialKey":"6ac292faa1315b4d858ab3a3d7d5933a","CurrentKSN":"FFFF9876543210E00001","TransactionKey":"042666b49184cfa368de9628d0397bc9","CreatedAt":"..."},"error":null}
```

Create an aes machine. `AlgorithmKey` is the key type: `AES128`, `AES192` or `AES256`.

```
$ curl -XPOST localhost:8095/machine -d '{"Algorithm":"aes","AlgorithmKey":"AES128","BaseDerivativeKey":"FEDCBA9876543210F1F1F1F1F1F1F1F1","KeySerialNumber":"123456789012345600000001"}'
{"ik":"1273671ea26ac29afa4d1084127652a1","machine":{"Algorithm":"aes","AlgorithmKey":"AES128","BaseDerivativeKey":"FEDCBA9876543210F1F1F1F1F1F1F1F1","KeySerialNumber":"123456789012345600000001","InitialKey":"1273671ea26ac29afa4d1084127652a1","CurrentKSN":"123456789012345600000001","TransactionKey":"4f21b565bad9835e112b6465635eae44","CreatedAt":"..."},"error":null}
```

Get one machine, or all machines:

```
$ curl localhost:8095/machine/6ac292faa1315b4d858ab3a3d7d5933a
{"machine":{"Algorithm":"des",...,"CurrentKSN":"FFFF9876543210E00001","TransactionKey":"042666b49184cfa368de9628d0397bc9","CreatedAt":"..."},"error":null}

$ curl localhost:8095/machines
{"machines":[{"Algorithm":"des",...},{"Algorithm":"aes",...}],"error":null}
```

Encrypt and decrypt a PIN. `Format` is a PIN block format such as `ISO-0` for des. aes always uses ISO-4, and its result changes on each call because ISO-4 adds random fill.

```
$ curl -XPOST localhost:8095/encrypt_pin/6ac292faa1315b4d858ab3a3d7d5933a -d '{"Pin":"1234","Pan":"4012345678909","Format":"ISO-0"}'
{"encrypted":"1b9c1845eb993a7a","error":null}

$ curl -XPOST localhost:8095/decrypt_pin/6ac292faa1315b4d858ab3a3d7d5933a -d '{"Encrypted":"1b9c1845eb993a7a","Pan":"4012345678909","Format":"ISO-0"}'
{"decrypted":"1234","error":null}
```

Generate a MAC. `Action` is `request` or `response`. For aes, `MacType` is `cmac` or `hmac`; des ignores it.

```
$ curl -XPOST localhost:8095/generate_mac/6ac292faa1315b4d858ab3a3d7d5933a -d '{"Action":"request","Data":"4012345678909D987"}'
{"generated":"9ccc78173fc4fb64","error":null}

$ curl -XPOST localhost:8095/generate_mac/1273671ea26ac29afa4d1084127652a1 -d '{"Action":"request","Data":"hello","MacType":"cmac"}'
{"generated":"3553b546f72923ccd6824cb572cdd893","error":null}
```

Encrypt and decrypt data. `Iv` is optional; when it is empty the server uses an IV of zeros. The decrypted data includes its zero padding.

```
$ curl -XPOST localhost:8095/encrypt_data/6ac292faa1315b4d858ab3a3d7d5933a -d '{"Action":"request","Data":"4012345678909D987"}'
{"encrypted":"fc0d53b7ea1fda9ee68aaf2e70d9b9506229be2aa993f04f","error":null}

$ curl -XPOST localhost:8095/decrypt_data/6ac292faa1315b4d858ab3a3d7d5933a -d '{"Action":"request","Data":"fc0d53b7ea1fda9ee68aaf2e70d9b9506229be2aa993f04f"}'
{"data":"4012345678909D987\u0000\u0000\u0000\u0000\u0000\u0000\u0000","error":null}
```

Generate the next KSN. This request has no body. The machine then uses the new KSN and its transaction key for the PIN, MAC and data endpoints.

```
$ curl -XPOST localhost:8095/generate_ksn/6ac292faa1315b4d858ab3a3d7d5933a
{"ksn":"ffff9876543210e00002","error":null}
```

## Supported and tested platforms

- 64-bit Linux (Ubuntu, Debian), macOS, and Windows
- Raspberry Pi

Note: 32-bit platforms have known issues and are not supported.

## Contributing

Yes please! Please open an issue or pull request. Moov's [Contributing guide](https://github.com/moov-io/ach/blob/master/CONTRIBUTING.md) and [Code of Conduct](https://github.com/moov-io/ach/blob/master/CODE_OF_CONDUCT.md) also apply to this project.

This project uses [Go Modules](https://go.dev/blog/using-go-modules) and Go v1.26 or newer. See [Golang's install instructions](https://golang.org/doc/install) for help setting up Go. You can download the source code and we offer [tagged and released versions](https://github.com/moov-io/dukpt/releases/latest) as well. We highly recommend you use a tagged release for production.

### Releasing

To make a release of dukpt simply open a pull request with `version.go` updated with the next version number. You'll also need to push the tag (i.e. `git push origin v1.0.0`) to origin in order for CI to make the release.

### Testing

We maintain a comprehensive suite of unit tests and recommend table-driven testing when a particular function warrants several very similar test cases. To run all tests, use `go test ./...` or `make check`. Current overall coverage can be found on [Codecov](https://app.codecov.io/gh/moov-io/dukpt/).


## Related projects
As part of Moov's initiative to offer open source fintech infrastructure, we have a large collection of active projects you may find useful:

- [Moov PIN Block](https://github.com/moov-io/pinblock) offers functions for personal identification management (PIN) and security.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
