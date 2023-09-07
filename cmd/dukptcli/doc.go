package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/moov-io/dukpt"
)

func help() {
	fmt.Printf(strings.TrimSpace(`
dukptcli is a tool for both tdes and aes derived unique key per transaction (dukpt) key management.

USAGE
   dukptcli [-v] [-algorithm] [-ik] [-tk] [-ep] [-dp] [-gm] [-en] [-de]

EXAMPLES
  dukptcli -v          Print the version of dukptcli (Example: %s)
  dukptcli -algorithm  Data encryption algorithm (options: des, aes)
  dukptcli -ik         Derive initial key from base derivative key and key serial number (or initial key id)
  dukptcli -tk         Derive transaction key (current transaction key) from initial key and key serial number
  dukptcli -ep         Encrypt pin block using dukpt transaction key
  dukptcli -dp         Decrypt pin block using dukpt transaction key
  dukptcli -gm         Generate mac using dukpt transaction key
  dukptcli -en         Encrypt data using dukpt transaction key
  dukptcli -de         Decrypt data using dukpt transaction key

FLAGS
`), dukpt.Version)
	fmt.Println("")
	flag.PrintDefaults()
}
