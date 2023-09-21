[![Moov Banner Logo](https://user-images.githubusercontent.com/20115216/104214617-885b3c80-53ec-11eb-8ce0-9fc745fb5bfc.png)](https://github.com/moov-io)

<p align="center">
  <a href="https://moov-io.github.io/dukpt/">Project Documentation</a>
  ·
  <a href="https://moov-io.github.io/dukpt/api/#overview">API Endpoints</a>
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
    - [DUPKT apis](#dupkt-apis)
    - [How to](#how-to)
    - [Command lines](#command-lines)
    - [Service Instance](#service-instance)
    - [Rest APIs](#rest-apis)
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

This project uses [Go Modules](https://go.dev/blog/using-go-modules) and Go v1.18 or newer. See [Golang's install instructions](https://golang.org/doc/install) for help setting up Go. You can download the source code and we offer [tagged and released versions](https://github.com/moov-io/dupkt/releases/latest) as well. We highly recommend you use a tagged release for production.

```
$ git@github.com:moov-io/dupkt.git

$ go get -u github.com/moov-io/dupkt
```

### DUPKT apis

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
    func DecryptData(currentKey, ksn, iv, ciphertext []byte, keyType, action string) (string, error)
```

- Utility function that used to get next key serial number 
```
    GenerateNextAesKsn(ksn []byte) ([]byte, error)
```

### How to

First step is to derive initial key in from base derivative key and key serial number (or initial key id). Base derivative key (BKD) can get from base derivative key id. The package don't specify how to get base derivative key.  

- des
```
    ik, err := DerivationOfInitialKey(bdk, ksn)
    if err != nil {
        return err
    }
```

- aes
```
    ik, err := DerivationOfInitialKey(bdk, initialKeyID)
    if err != nil {
        return err
    }
```

Second step is to generate transaction key in from generated initial key and key serial number.

```
    transactionKey, err := DeriveCurrentTransactionKey(ik, ksn)
    if err != nil {
        return err
    }
```

Data (pin, mac, normal data) is encrypted/decrypted using generated initial key and transaction key

- des
```
    eryptedPin, err := EncryptPin(transactionKey, pin, pan, FormatVersion)
    if err != nil {
        return err
    }

    decryptedPin, err := DecryptPin(transactionKey, encryptedPin, pan, FormatVersion)
    if err != nil {
        return err
    }
```

- aes
```
	encPinblock, err := EncryptPin(transactionKey, ksn, pin, pan, KeyAES128Type)
    if err != nil {
        return err
    }

	decPinblock, err := DecryptPin(transactionKey, ksn, encPinblock, pan, KeyAES128Type)
    if err != nil {
        return err
    }
```

### Command lines

```
dukptcli is a tool for both tdes and aes derived unique key per transaction (dukpt) key management.

USAGE
   dukptcli [-v] [-algorithm] [-ik] [-tk] [-ep] [-dp] [-gm] [-en] [-de]

EXAMPLES
  dukptcli -v          Print the version of dukptcli (Example: v1.0.0)
  dukptcli -algorithm  Data encryption algorithm (options: des, aes)
  dukptcli -ik         Derive initial key from base derivative key and key serial number (or initial key id)  
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
        key type of aes (options: aes128, aes192, aes256 (default "aes128")
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
        derive initial key from base derivative key and key serial number (or initial key id)
  -ik.bdk string
        base derivative key
  -ik.kid string
        initial key id
  -ik.ksn string
        key serial number
  -tk
        derive transaction key (current transaction key) from initial key and key serial number
  -tk.ik string
        initial key
  -tk.ksn string
        key serial number
  -v    Print dupkt cli version
```

User should use main flag and sub flag. algorithm.key_type flag is a sub flag of algorithm flag.

There are some execution flags in this cli
```
    dukptcli -ik         Derive initial key from base derivative key and key serial number (or initial key id)  
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
| GET    |              | /machines          | Get Machines   |
| GET    |              | /machine/{ik}      | Get Machine    |
| POST   |              | /machine           | Create Machine |
| POST   | JSON         | /generate_ksn/{ik} | Generate KSN   |
| POST   | JSON         | /encrypt_pin/{ik}  | Encrypt PIN    | 
| POST   | JSON         | /decrypt_pin/{ik}  | Decrypt Pin    |
| POST   | JSON         | /generate_mac/{ik} | Generate Mac   |
| POST   | JSON         | /encrypt_data/{ik} | Encrypt Data   |
| POST   | JSON         | /decrypt_data/{ik} | Decrypt Data   |

User can create web service using following http handler 
```
	handler = server.MakeHTTPHandler(svc)
```

## Supported and tested platforms

- 64-bit Linux (Ubuntu, Debian), macOS, and Windows
- Raspberry Pi

Note: 32-bit platforms have known issues and are not supported.

## Contributing

Yes please! Please review our [Contributing guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) to get started!

This project uses [Go Modules](https://go.dev/blog/using-go-modules) and Go v1.18 or newer. See [Golang's install instructions](https://golang.org/doc/install) for help setting up Go. You can download the source code and we offer [tagged and released versions](https://github.com/moov-io/imagecashletter/releases/latest) as well. We highly recommend you use a tagged release for production.

### Releasing

To make a release of dupkt simply open a pull request with `CHANGELOG.md` and `version.go` updated with the next version number and details. You'll also need to push the tag (i.e. `git push origin v1.0.0`) to origin in order for CI to make the release.

### Testing

We maintain a comprehensive suite of unit tests and recommend table-driven testing when a particular function warrants several very similar test cases. To run all test files in the current directory, use `go test`. Current overall coverage can be found on [Codecov](https://app.codecov.io/gh/moov-io/imagecashletter/).


## Related projects
As part of Moov's initiative to offer open source fintech infrastructure, we have a large collection of active projects you may find useful:

- [Moov DUPKT](https://github.com/moov-io/pinblock) offers functions for personal identification management (PIN) and security.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
