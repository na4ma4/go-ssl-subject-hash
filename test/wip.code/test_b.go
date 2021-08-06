//nolint:deadcode,gosimple,unused
package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"log"
	"strings"
)

func test_b() {
	buf, err := ioutil.ReadFile("test/ca-cert-Amazon_Root_CA_1.pem")
	checkErr(err)
	b, _ := pem.Decode(buf)
	cert, err := x509.ParseCertificate(b.Bytes)
	checkErr(err)

	log.Printf("Test[r]: %x", cert.RawSubject)
	// log.Printf("Test[s]: %s", cert.RawSubject)

	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(cert.RawSubject, &subject); err != nil {
		checkErr(err)
	}
	// log.Printf("Subject: %#v", subject)

	sb := bytes.NewBuffer(nil)
	for j, _ := range subject {
		// log.Printf("Sub[%d]: %x", j, subject[j])
		for i := range subject[j] {
			// log.Printf("Sub1(Type): %x", subject[j][i].Type)
			// log.Printf("Sub1(Value): %s", subject[j][i].Value)
			subject[j][i].Value = strings.ToLower(subject[j][i].Value.(string))
			// log.Printf("Sub1(Value): %s", subject[j][i].Value)
		}
		// log.Printf("Sub[%d]: %x", j, subject[j])

		b, err := asn1.Marshal(subject[j])
		checkErr(err)
		b[9] = 0x0c
		log.Printf("Sub[%d]: %x", j, b)
		_, err = sb.Write(b)
		checkErr(err)
		// if v, ok := sub.(pkix.AttributeTypeAndValue); ok {
		// 	log.Printf("PKIX: %x", v)
		// } else {
		// }
		// log.Printf("Sub.Type: %x", sub.Type)
		// log.Printf("Sub.Value: %x", sub.Value)
	}

	// sb, err := asn1.Marshal(subject)
	// checkErr(err)
	// log.Printf("SubReass: %x", sb)

	// log.Printf("Subject: %s", subject.String())
	h := sha1.Sum(sb.Bytes())
	n := truncatedHash(h, 4)
	log.Printf("Sum[FINAL]: (%x) [%x]", h, n)
}
