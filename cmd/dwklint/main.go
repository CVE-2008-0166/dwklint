package main

import (
	"crypto/x509"
	"fmt"
	"os"

	dwklint "github.com/CVE-2008-0166/dwklint"
)

func main() {
	exitCode := dwklint.Error
	defer func() { os.Exit(int(exitCode)) }()

	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <blocklist_directory> <cert_file>\n", os.Args[0])
		return
	}

	if err := dwklint.LoadBlocklists(os.Args[1]); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	certfile, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	cert, err := x509.ParseCertificate(certfile)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	output := ""
	exitCode = dwklint.HasDebianWeakKey(cert)
	switch exitCode {
	case dwklint.NotWeak:
		output = "Not Weak"
	case dwklint.UnknownButTLSBRExceptionGranted:
		output = "Unknown, but TLS BR exception granted (RSA key size >8192-bits)"
	case dwklint.Weak:
		output = "WEAK!"
	case dwklint.Unknown:
		output = "Unknown"
	case dwklint.Error:
		output = "Error"
	}

	fmt.Printf("%s\n", output)
}
