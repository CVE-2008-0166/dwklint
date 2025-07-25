package dwklint

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"

	"zombiezen.com/go/sqlite"
)

type DebianWeakKeyStatus int

const (
	// Pass:
	NotWeak DebianWeakKeyStatus = iota
	UnknownButTLSBRExceptionGranted
	// Fail:
	Weak
	Unknown
	Error
)

var dbConn *sqlite.Conn

func OpenBlocklistDatabase(blocklistDatabasePath string) error {
	var err error
	dbConn, err = sqlite.OpenConn(blocklistDatabasePath, sqlite.OpenReadOnly)
	return err
}

func CloseBlocklistDatabase() {
	if dbConn != nil {
		dbConn.Close()
	}
}

func HasDebianWeakKey(cert *x509.Certificate) DebianWeakKeyStatus {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		r, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return Error
		}

		sha256Fingerprint := sha256.Sum256(r.N.Bytes())
		stmt, _, err := dbConn.PrepareTransient(fmt.Sprintf("SELECT 1 FROM debian_weak_modulus_%d WHERE SHA256_FINGERPRINT=$1", r.N.BitLen()))
		if err != nil {
			if !strings.Contains(err.Error(), "no such table") {
				return Error
			} else if r.N.BitLen() > 8192 {
				return UnknownButTLSBRExceptionGranted
			} else {
				return Unknown
			}
		}

		defer stmt.Finalize()
		stmt.BindBytes(1, sha256Fingerprint[:])

		wasRowReturned, err := stmt.Step()
		if err != nil {
			return Error
		} else if wasRowReturned {
			return Weak
		} else {
			return NotWeak
		}

	case x509.ECDSA:
		e, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return Error
		}

		p := e.Params()
		if p == nil {
			return Error
		}

		var tableSuffix string
		switch p.Name {
		case "P-256":
			tableSuffix = "secp256r1"
		case "P-384":
			tableSuffix = "secp384r1"
		case "P-521":
			tableSuffix = "secp521r1"
		default:
			return Unknown
		}

		sha256Fingerprint := sha256.Sum256(e.X.Bytes())
		stmt, _, err := dbConn.PrepareTransient(fmt.Sprintf("SELECT 1 FROM debian_weak_xcoord_%s WHERE SHA256_FINGERPRINT=$1", tableSuffix))
		if err != nil {
			if !strings.Contains(err.Error(), "no such table") {
				return Error
			} else {
				return Unknown
			}
		}

		defer stmt.Finalize()
		stmt.BindBytes(1, sha256Fingerprint[:])

		wasRowReturned, err := stmt.Step()
		if err != nil {
			return Error
		} else if wasRowReturned {
			return Weak
		} else {
			return NotWeak
		}

	default:
		return Unknown
	}
}
