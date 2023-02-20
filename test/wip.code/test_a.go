//nolint:deadcode,unused // testing
package main

import (
	"crypto/sha1" //nolint:gosec // openssl compat
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"log"
	"strings"
)

//nolint:funlen // testing
func testA() {
	testPrincipal := []byte{
		0x30, 0x39, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x75, 0x73, 0x31,
		0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x06, 0x61, 0x6D, 0x61, 0x7A, 0x6F, 0x6E,
		0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x10, 0x61, 0x6D, 0x61, 0x7A, 0x6F,
		0x6E, 0x20, 0x72, 0x6F, 0x6F, 0x74, 0x20, 0x63, 0x61, 0x20, 0x31,
	}
	testArray := [][]byte{
		{
			0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x0C, 0x02, 0x75, 0x73,
		},
		{
			0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x06, 0x61,
			0x6D, 0x61, 0x7A, 0x6F, 0x6E,
		},
		{
			0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x10, 0x61,
			0x6D, 0x61, 0x7A, 0x6F, 0x6E, 0x20, 0x72, 0x6F, 0x6F, 0x74, 0x20, 0x63,
			0x61, 0x20, 0x31,
		},
	}

	buf, err := ioutil.ReadFile("test/ca-cert-Amazon_Root_CA_1.pem")
	checkErr(err)
	b, _ := pem.Decode(buf)
	cert, err := x509.ParseCertificate(b.Bytes)
	checkErr(err)

	log.Printf("Test[P]: %x", testPrincipal)

	var principal pkix.RDNSequence
	var rest []byte
	if rest, err = asn1.Unmarshal(testPrincipal, &principal); err != nil {
		checkErr(err)
	} else {
		log.Printf("Rest[%d]: %x", len(rest), rest)
	}
	pb, err := asn1.Marshal(principal)
	checkErr(err)
	log.Printf("Test[PB]: %x", pb)

	// for j, sub := range principal {
	// 	log.Printf("Sub[%d]: %x", j, sub)
	// 	for i := range sub {
	// 		log.Printf("Sub1(string): %s", sub[i].Type.String())
	// 		log.Printf("Sub1(Type): %x", sub[i].Type)
	// 		log.Printf("Sub1(Value): %s", sub[i].Value)
	// 		sub[i].Value = strings.ToLower(sub[i].Value.(string))
	// 		log.Printf("Sub1(Value): %s", sub[i].Value)
	// 	}
	// 	log.Printf("Sub[%d]: %x", j, sub)
	// 	b, err := asn1.Marshal(sub)
	// 	checkErr(err)
	// 	log.Printf("SubReass: %x", b)
	// 	// if v, ok := sub.(pkix.AttributeTypeAndValue); ok {
	// 	// 	log.Printf("PKIX: %x", v)
	// 	// } else {
	// 	// }
	// 	// log.Printf("Sub.Type: %x", sub.Type)
	// 	// log.Printf("Sub.Value: %x", sub.Value)
	// }

	for i, v := range testArray {
		log.Printf("Test[%d] %x", i, v)
		var subpart pkix.RelativeDistinguishedNameSET
		if _, err = asn1.Unmarshal(v, &subpart); err != nil {
			checkErr(err)
		}
		log.Printf("SubPart[%d]: %x", i, subpart)
		// log.Printf("SubPart[%d]: %s", i, subpart.String())
		for j, sub := range subpart {
			log.Printf("Subpart[%d/%d]: %s", i, j, sub.Value)
		}
		var b []byte
		b, err = asn1.Marshal(subpart)
		checkErr(err)
		b[9] = 0x0c
		log.Printf("TestA[%d] %x", i, b)
		// h := sha1.Sum(v)
		// n := truncatedHash(h, 4)
		// log.Printf("Sum[%d]: (%x) [%x]", i, h, n)
	}

	log.Printf("Test[r]: %x", cert.RawSubject)
	// log.Printf("Test[s]: %s", cert.RawSubject)

	var subject pkix.RDNSequence
	// var subject asn1.RawValue
	// var subject asn1.ObjectIdentifier
	// var subject []byte
	// var subject struct {
	// 	Algo      pkix.AlgorithmIdentifier
	// 	BitString asn1.BitString
	// }

	if rest, err = asn1.Unmarshal(cert.RawSubject, &subject); err != nil {
		checkErr(err)
	} else {
		log.Printf("Rest[%d]: %x", len(rest), rest)
	}
	log.Printf("Subject: %#v", subject)

	for j := range subject {
		log.Printf("Sub[%d]: %x", j, subject[j])
		for i := range subject[j] {
			log.Printf("Sub1(Type): %x", subject[j][i].Type)
			log.Printf("Sub1(Value): %s", subject[j][i].Value)
			subject[j][i].Value = strings.ToLower(subject[j][i].Value.(string))
			log.Printf("Sub1(Value): %s", subject[j][i].Value)
		}
		log.Printf("Sub[%d]: %x", j, subject[j])

		b, serr := asn1.Marshal(subject[j])
		checkErr(serr)
		b[9] = 0x0c
		log.Printf("SubR[%d]: %x", j, b)
		// if v, ok := sub.(pkix.AttributeTypeAndValue); ok {
		// 	log.Printf("PKIX: %x", v)
		// } else {
		// }
		// log.Printf("Sub.Type: %x", sub.Type)
		// log.Printf("Sub.Value: %x", sub.Value)
	}

	sb, err := asn1.Marshal(subject)
	checkErr(err)
	log.Printf("SubReass: %x", sb)

	// log.Printf("Subject: %s", subject.String())

	log.Printf("SubjectKeyId: %08x", sha1.Sum(cert.SubjectKeyId))   //nolint:gosec // openssl compat
	log.Printf("subject.String(): %08x", sha1.Sum(cert.RawSubject)) //nolint:gosec // openssl compat
	log.Printf("sha256: %08x", sha256.Sum256(cert.RawSubject))
}
