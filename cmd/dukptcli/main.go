package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/moov-io/dukpt"
	"github.com/moov-io/dukpt/pkg"
)

var (
	flagVersion = flag.Bool("v", false, "Print dupkt cli version")

	flagAlgorithm        = flag.String("algorithm", "des", "data encryption algorithm (options: des, aes)")
	flagAlgorithmKeyType = flag.String("algorithm.key_type", "aes128", "key type of aes (options: aes128, aes192, aes256")

	flagInitialKey    = flag.Bool("ik", false, "derive initial key from base derivative key and key serial number (or initial key id)")
	flagInitialKeyBKD = flag.String("ik.bdk", "", "base derivative key")
	flagInitialKeyKSN = flag.String("ik.ksn", "", "key serial number")
	flagInitialKeyKID = flag.String("ik.kid", "", "initial key id")

	flagTransactionKey    = flag.Bool("tk", false, "derive transaction key (current transaction key) from initial key and key serial number")
	flagTransactionKeyIK  = flag.String("tk.ik", "", "initial key")
	flagTransactionKeyKSN = flag.String("tk.ksn", "", "key serial number")

	flagEncryptPin       = flag.Bool("ep", false, "encrypt pin block using dukpt transaction key")
	flagEncryptPinTK     = flag.String("ep.tk", "", "current transaction key")
	flagEncryptPinKSN    = flag.String("ep.ksn", "", "key serial number")
	flagEncryptPinPin    = flag.String("ep.pin", "", "not formatted pin string")
	flagEncryptPinPan    = flag.String("ep.pan", "", "not formatted pan string")
	flagEncryptPinFormat = flag.String("ep.format", "", "pin block format (ISO-0, ISO-1, ISO-2, ISO-3, ISO-4, ANSI, ECI1, ECI2, ECI3, ECI4, VISA1, VISA2, VISA3, VISA4)")

	flagDecryptPin       = flag.Bool("dp", false, "decrypt pin block using dukpt transaction key")
	flagDecryptPinTK     = flag.String("dp.tk", "", "current transaction key")
	flagDecryptPinKSN    = flag.String("dp.ksn", "", "key serial number")
	flagDecryptPinPin    = flag.String("dp.pin", "", "encrypted text transformed from plaintext using an encryption algorithm")
	flagDecryptPinPan    = flag.String("dp.pan", "", "not formatted pan string")
	flagDecryptPinFormat = flag.String("dp.format", "", "pin block format (ISO-0, ISO-1, ISO-2, ISO-3, ISO-4, ANSI, ECI1, ECI2, ECI3, ECI4, VISA1, VISA2, VISA3, VISA4)")

	flagGenerateMac       = flag.Bool("gm", false, "generate mac using dukpt transaction key")
	flagGenerateMacTK     = flag.String("gm.tk", "", "current transaction key")
	flagGenerateMacKSN    = flag.String("gm.ksn", "", "key serial number")
	flagGenerateMacData   = flag.String("gm.data", "", "not formatted request data")
	flagGenerateMacAction = flag.String("gm.action", "request", "request or response action")
	flagGenerateMacType   = flag.String("gm.type", "cmac", "cmac or hmac style (is valid using aes algorithm)")

	flagEncrypt       = flag.Bool("en", false, "encrypt data using dukpt transaction key")
	flagEncryptTK     = flag.String("en.tk", "", "current transaction key")
	flagEncryptKSN    = flag.String("en.ksn", "", "key serial number")
	flagEncryptIV     = flag.String("en.iv", "", "initial vector (not formatted string)")
	flagEncryptData   = flag.String("en.data", "", "not formatted request data")
	flagEncryptAction = flag.String("en.action", "request", "request or response action")

	flagDecrypt       = flag.Bool("de", false, "decrypt data using dukpt transaction key")
	flagDecryptTK     = flag.String("de.tk", "", "current transaction key")
	flagDecryptKSN    = flag.String("de.ksn", "", "key serial number")
	flagDecryptIV     = flag.String("de.iv", "", "initial vector (not formatted string)")
	flagDecryptData   = flag.String("de.data", "", "encrypted text transformed from plaintext using an encryption algorithm")
	flagDecryptAction = flag.String("de.action", "request", "request or response action")
)

func main() {
	flag.Usage = help
	flag.Parse()
	params := cliParams{}

	switch {
	case *flagVersion:
		fmt.Printf("moov-io/dukpt:%s cli tool\n", dukpt.Version)
		return
	}

	// checking algorithm
	if *flagAlgorithm == "aes" && *flagAlgorithmKeyType == "" {
		fmt.Printf("please select key type with algorithm.key_type flag\n")
		os.Exit(1)
	}

	params.Algorithm = *flagAlgorithm
	params.AlgorithmKeyType = *flagAlgorithmKeyType

	// checking ik params
	if *flagInitialKey {
		if *flagInitialKeyBKD == "" {
			fmt.Printf("please select base derivative key with ik.bdk flag\n")
			os.Exit(1)
		}
		if *flagAlgorithm == "aes" && *flagInitialKeyKID == "" {
			fmt.Printf("please select initial key id with ik.kid flag\n")
			os.Exit(1)
		}
		if *flagAlgorithm == "des" && *flagInitialKeyKSN == "" {
			fmt.Printf("please select key serial number with ik.ksn flag\n")
			os.Exit(1)
		}

		params.BKD = *flagInitialKeyBKD
		params.KID = *flagInitialKeyKID
		params.KSN = *flagInitialKeyKSN

		makeFuncCall(initialKey, params)
		return
	}

	// checking tk params
	if *flagTransactionKey {
		if *flagTransactionKeyIK == "" {
			fmt.Printf("please select initial key with tk.ik flag\n")
			os.Exit(1)
		}
		if *flagTransactionKeyKSN == "" {
			fmt.Printf("please select key serial number with tk.ksn flag\n")
			os.Exit(1)
		}

		params.IK = *flagTransactionKeyIK
		params.KSN = *flagTransactionKeyKSN

		makeFuncCall(transactionKey, params)
		return
	}

	// checking encrypt pin params
	if *flagEncryptPin {
		if *flagEncryptPinTK == "" {
			fmt.Printf("please select current transaction key with ep.tk flag\n")
			os.Exit(1)
		}
		if *flagEncryptPinPin == "" {
			fmt.Printf("please select pin string with ep.pin flag\n")
			os.Exit(1)
		}
		if *flagEncryptPinPan == "" {
			fmt.Printf("please select pan string with ep.pan flag\n")
			os.Exit(1)
		}

		if *flagAlgorithm == "aes" {
			if *flagEncryptPinKSN == "" {
				fmt.Printf("please select key serial number with ep.ksn flag\n")
				os.Exit(1)
			}
		} else {
			if *flagEncryptPinFormat == "" {
				fmt.Printf("please select pin block format with ep.formst flag\n")
				os.Exit(1)
			}
		}

		params.TK = *flagEncryptPinTK
		params.PIN = *flagEncryptPinPin
		params.PAN = *flagEncryptPinPan
		params.KSN = *flagEncryptPinKSN
		params.Format = *flagEncryptPinFormat

		makeFuncCall(encryptPin, params)
		return
	}

	// checking decrypt pin params
	if *flagDecryptPin {
		if *flagDecryptPinTK == "" {
			fmt.Printf("please select current transaction key with dp.tk flag\n")
			os.Exit(1)
		}
		if *flagDecryptPinPin == "" {
			fmt.Printf("please select encrypted text with dp.pin flag\n")
			os.Exit(1)
		}
		if *flagDecryptPinPan == "" {
			fmt.Printf("please select pan string with dp.pan flag\n")
			os.Exit(1)
		}

		if *flagAlgorithm == "aes" {
			if *flagDecryptPinKSN == "" {
				fmt.Printf("please select key serial number with dp.ksn flag\n")
				os.Exit(1)
			}
		} else {
			if *flagDecryptPinFormat == "" {
				fmt.Printf("please select pin block format with dp.formst flag\n")
				os.Exit(1)
			}
		}

		params.TK = *flagDecryptPinTK
		params.PIN = *flagDecryptPinPin
		params.PAN = *flagDecryptPinPan
		params.KSN = *flagDecryptPinKSN
		params.Format = *flagDecryptPinFormat

		makeFuncCall(decryptPin, params)
		return
	}

	// checking generate mac params
	if *flagGenerateMac {
		if *flagGenerateMacTK == "" {
			fmt.Printf("please select current transaction key with gm.tk flag\n")
			os.Exit(1)
		}
		if *flagGenerateMacData == "" {
			fmt.Printf("please select request data string with gm.data flag\n")
			os.Exit(1)
		}
		if *flagGenerateMacAction != pkg.ActionRequest && *flagGenerateMacAction != pkg.ActionResponse {
			fmt.Printf("please select valid action with gm.action flag\n")
			os.Exit(1)
		}

		if *flagAlgorithm == "aes" {
			if *flagGenerateMacKSN == "" {
				fmt.Printf("please select key serial number with gm.ksn flag\n")
				os.Exit(1)
			}
			if *flagGenerateMacType != "cmac" && *flagGenerateMacType != "hmac" {
				fmt.Printf("please select valid mac type with gm.type flag\n")
				os.Exit(1)
			}
		}

		params.TK = *flagGenerateMacTK
		params.Plaintext = *flagGenerateMacData
		params.Action = *flagGenerateMacAction
		params.MacType = *flagGenerateMacType
		params.KSN = *flagGenerateMacKSN

		makeFuncCall(generateMac, params)
		return
	}

	// checking encrypt data params
	if *flagEncrypt {
		if *flagEncryptTK == "" {
			fmt.Printf("please select current transaction key with en.tk flag\n")
			os.Exit(1)
		}
		if *flagEncryptIV == "" {
			fmt.Printf("please select initial vector with en.iv flag\n")
			os.Exit(1)
		}
		if *flagEncryptData == "" {
			fmt.Printf("please select request data with en.data flag\n")
			os.Exit(1)
		}

		if *flagAlgorithm == "aes" {
			if *flagEncryptKSN == "" {
				fmt.Printf("please select key serial number with en.ksn flag\n")
				os.Exit(1)
			}
		}

		params.TK = *flagEncryptTK
		params.Plaintext = *flagEncryptData
		params.IV = *flagEncryptIV
		params.KSN = *flagEncryptKSN
		params.Action = *flagEncryptAction

		makeFuncCall(encryptData, params)
		return
	}

	// checking decrypt data params
	if *flagDecrypt {
		if *flagDecryptTK == "" {
			fmt.Printf("please select current transaction key with de.tk flag\n")
			os.Exit(1)
		}
		if *flagDecryptIV == "" {
			fmt.Printf("please select initial vector with de.iv flag\n")
			os.Exit(1)
		}
		if *flagDecryptData == "" {
			fmt.Printf("please select encrypted text with de.data flag\n")
			os.Exit(1)
		}

		if *flagAlgorithm == "aes" {
			if *flagDecryptKSN == "" {
				fmt.Printf("please select key serial number with de.ksn flag\n")
				os.Exit(1)
			}
		}

		params.TK = *flagDecryptTK
		params.Ciphertext = *flagDecryptData
		params.IV = *flagDecryptIV
		params.KSN = *flagDecryptKSN
		params.Action = *flagDecryptAction

		makeFuncCall(decryptData, params)
		return
	}

	flag.Usage()
	os.Exit(1)
}
