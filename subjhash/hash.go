package subjhash

//nolint:gosec // crypto/sha1, it's weak, openssl uses it.
import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidCertificate is returned when an invalid certificate is supplied.
var ErrInvalidCertificate = errors.New("invalid certificate")

// SubjHash is the certificate hash with fmt.Stringer interface support.
type SubjHash [4]byte

func (s SubjHash) String() string {
	return fmt.Sprintf("%x", [4]byte(s))
}

// Issuer takes a *x509.Certificate and returns the openssl 1.0.1+ compatible
// issuer_hash for the certificate.
func Issuer(cert *x509.Certificate) (SubjHash, error) {
	if cert == nil {
		return SubjHash{}, ErrInvalidCertificate
	}

	return hashRawValue(cert.RawIssuer)
}

// Subject takes a *x509.Certificate and returns the openssl 1.0.1+ compatible
// subject_hash for the certificate.
func Subject(cert *x509.Certificate) (SubjHash, error) {
	if cert == nil {
		return SubjHash{}, ErrInvalidCertificate
	}

	return hashRawValue(cert.RawSubject)
}

func hashRawValue(v []byte) (SubjHash, error) {
	var (
		subject pkix.RDNSequence
		hash    [4]byte
	)

	if _, err := asn1.Unmarshal(v, &subject); err != nil {
		return hash, fmt.Errorf("unable to unmarshal ASN.1 subject: %w", err)
	}

	sb := bytes.NewBuffer(nil)

	for j := range subject {
		for i := range subject[j] {
			if v, ok := subject[j][i].Value.(string); ok {
				subject[j][i].Value = strings.ToLower(v)
			}
		}

		b, err := remarshalASN1(subject[j])
		if err != nil {
			return hash, fmt.Errorf("unable to remarshal ASN.1 RDN segment: %w", err)
		}

		if _, err = sb.Write(b); err != nil {
			return hash, fmt.Errorf("unable to write bytes to buffer: %w", err)
		}
	}

	h := sha1.Sum(sb.Bytes()) //nolint:gosec // it's weak, openssl uses it.
	for i := 0; i < 4; i++ {
		hash[3-i] = h[i]
	}

	return hash, nil
}

//nolint:wrapcheck // it's wrapped in Certificate.
func remarshalASN1(val interface{}) ([]byte, error) {
	b, err := asn1.Marshal(val)
	if len(b) > 9 {
		b[9] = asn1.TagUTF8String
	}

	return b, err
}
