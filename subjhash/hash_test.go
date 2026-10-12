package subjhash_test

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/na4ma4/go-ssl-subject-hash/subjhash"
)

const caCertsDir = "../testdata/ca-certs/"

// skipCertHashes contains certificates that can't be parsed by the current Go
// version, so they are skipped in the table driven tests.
//
//nolint:gochecknoglobals // list of certificates to skip in the tests.
var skipCertHashes = map[string]string{
	"349f2832.0": "negative serial number (pre go1.23 worked)",
}

// readCertificate reads and parses the PEM encoded certificate stored in filename.
func readCertificate(tb testing.TB, filename string) *x509.Certificate {
	tb.Helper()

	cd, err := os.ReadFile(filename)
	if err != nil {
		tb.Fatalf("unable to read certificate file %s: %v", filename, err)
	}

	p, _ := pem.Decode(cd)
	if p == nil {
		tb.Fatalf("unable to decode PEM block of %s", filename)
	}

	c, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		tb.Fatalf("unable to parse certificate %s: %v", filename, err)
	}

	return c
}

// checkCertFileHash checks that both the subject and the issuer hash of the
// certificate stored in filename are equal to the given hash.
func checkCertFileHash(tb testing.TB, filename, hash string) {
	tb.Helper()

	c := readCertificate(tb, filename)

	subjectHash, err := subjhash.Subject(c)
	if err != nil {
		tb.Fatalf("unable to calculate subject hash of %s: %v", filename, err)
	}

	if got := subjectHash.String(); got != hash {
		tb.Errorf("unexpected subject hash for %s: got %q, want %q", filename, got, hash)
	}

	issuerHash, err := subjhash.Issuer(c)
	if err != nil {
		tb.Fatalf("unable to calculate issuer hash of %s: %v", filename, err)
	}

	if got := issuerHash.String(); got != hash {
		tb.Errorf("unexpected issuer hash for %s: got %q, want %q", filename, got, hash)
	}
}

// checkCertHash checks that the subject and the issuer hash of the certificate
// stored in filename are equal to the filename itself, as it is how openssl
// names the certificate hash files.
func checkCertHash(tb testing.TB, filename string) {
	tb.Helper()

	checkCertFileHash(tb, filename, strings.TrimSuffix(filepath.Base(filename), ".0"))
}

func TestNilCertificate(t *testing.T) {
	t.Parallel()

	for name, hashFunc := range map[string]func(*x509.Certificate) (subjhash.SubjHash, error){
		"Subject": subjhash.Subject,
		"Issuer":  subjhash.Issuer,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h, err := hashFunc(nil)
			if !errors.Is(err, subjhash.ErrInvalidCertificate) {
				t.Errorf("unexpected error: got %v, want %v", err, subjhash.ErrInvalidCertificate)
			}

			if h != (subjhash.SubjHash{}) {
				t.Errorf("unexpected hash: got %s, want empty hash", h)
			}
		})
	}
}

func TestStackoverflowExample(t *testing.T) {
	t.Parallel()

	checkCertFileHash(t, "../testdata/stackoverflow-example.pem", "5ba4b7de")
}

func TestCACertHashes(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(caCertsDir)
	if err != nil {
		t.Fatalf("unable to read directory %s: %v", caCertsDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if reason, skip := skipCertHashes[entry.Name()]; skip {
			t.Logf("skipping %s: %s", entry.Name(), reason)

			continue
		}

		t.Run(entry.Name(), func(t *testing.T) {
			t.Parallel()

			checkCertHash(t, caCertsDir+entry.Name())
		})
	}
}

func TestTrickyCertificates(t *testing.T) {
	t.Parallel()

	t.Run("negative serial number", func(t *testing.T) {
		t.Parallel()

		filename := caCertsDir + "349f2832.0" // /O=Agencia Catalana de Certificacio (NIF Q-0801176-I)/

		cd, err := os.ReadFile(filename)
		if err != nil {
			t.Fatalf("unable to read certificate file %s: %v", filename, err)
		}

		p, _ := pem.Decode(cd)
		if p == nil {
			t.Fatalf("unable to decode PEM block of %s", filename)
		}

		if _, err = x509.ParseCertificate(p.Bytes); err == nil {
			t.Errorf("expected error when parsing certificate %s, got nil", filename)
		}
	})

	for name, filename := range map[string]string{
		"EE Certification Centre Root CA": caCertsDir + "128805a3.0", // /C=EE/O=AS Sertifitseerimiskeskus/CN=EE Certification Centre Root CA/emailAddress=pki@sk.ee
		"E-Tugra Certification Authority": caCertsDir + "5273a94c.0", // /C=TR/L=Ankara/O=E-Tuğra EBG Bilişim Teknolojileri ve Hizmetleri A.Ş./OU=E-Tugra Sertifikasyon Merkezi/CN=E-Tugra Certification Authority
		"Microsec e-Szigno Root CA 2009":  caCertsDir + "8160b96c.0", // /C=HU/L=Budapest/O=Microsec Ltd./CN=Microsec e-Szigno Root CA 2009/emailAddress=info@e-szigno.hu
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			checkCertHash(t, filename)
		})
	}
}
