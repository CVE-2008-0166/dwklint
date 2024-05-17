package dwklint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
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

var blocklists map[string]*map[[sha256.Size]byte]struct{}

// Load Debian weak key blocklists from the given directory, which should contain the CSV files from https://github.com/CVE-2008-0166/dwk_blocklists
func LoadBlocklists(dwkBlocklistPath string) error {
	// Initialize the map of blocklists.
	blocklists = make(map[string]*map[[sha256.Size]byte]struct{})

	// Find all files in the directory.
	if files, err := os.ReadDir(dwkBlocklistPath); err != nil {
		return err
	} else {
		// Loop through all files in the directory.
		for _, file := range files {
			// Parse the filename to determine the blocklist type and key size/curve.
			var blType, keyDetail string
			filename := strings.ReplaceAll(file.Name(), "_", " ")
			filename = strings.ReplaceAll(filename, ".", " ")
			if n, _ := fmt.Sscanf(filename, "sha256 %s %s csv", &blType, &keyDetail); n != 2 {
				continue // Not a blocklist.
			}

			// Determine the blocklist name.
			blName := ""
			switch blType {
			case "modulus":
				blName = "RSA-" + keyDetail
			case "xcoord":
				switch keyDetail {
				case "secp256r1":
					blName = elliptic.P256().Params().Name
				case "secp384r1":
					blName = elliptic.P384().Params().Name
				case "secp521r1":
					blName = elliptic.P521().Params().Name
				default:
					return fmt.Errorf("unknown curve %s", keyDetail)
				}
			}

			// Initialize the map for this blocklist.
			m := make(map[[sha256.Size]byte]struct{})
			blocklists[blName] = &m

			// Open the CSV blocklist file.
			f, err := os.Open(dwkBlocklistPath + "/" + file.Name())
			if err != nil {
				return err
			}
			defer f.Close()

			// Read the CSV file.
			r := csv.NewReader(f)
			r.FieldsPerRecord = 1
			lines, err := r.ReadAll()
			if err != nil {
				return err
			}

			// Add each hash entry to the blocklist map.
			for _, line := range lines {
				if h, err := hex.DecodeString(line[0]); err != nil {
					return err
				} else {
					var hash [sha256.Size]byte
					copy(hash[:], h)
					m[hash] = struct{}{}
				}
			}
		}

		return nil
	}
}

func HasDebianWeakKey(cert *x509.Certificate) DebianWeakKeyStatus {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if r, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
			return Error
		} else if bl, ok := blocklists[fmt.Sprintf("RSA-%d", r.N.BitLen())]; !ok {
			if r.N.BitLen() > 8192 {
				return UnknownButTLSBRExceptionGranted
			} else {
				return Unknown
			}
		} else if _, ok := (*bl)[sha256.Sum256(r.N.Bytes())]; ok {
			return Weak
		} else {
			return NotWeak
		}

	case x509.ECDSA:
		if e, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
			return Error
		} else if p := e.Params(); p == nil {
			return Error
		} else if bl, ok := blocklists[p.Name]; !ok {
			return Unknown
		} else if _, ok := (*bl)[sha256.Sum256(e.X.Bytes())]; ok {
			return Weak
		} else {
			return NotWeak
		}

	default:
		return Unknown
	}
}
