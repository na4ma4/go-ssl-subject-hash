package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"log"

	"github.com/na4ma4/go-ssl-subject-hash/subjhash"
)

func test_c() {
	soExample, err := base64.StdEncoding.DecodeString("MIHMMQswCQYDVQQGDAJkZTERMA8GA1UECAwIYsO2ciBsaW4xEjAQBgNVBAcMCWLDlnIgbCBpbjEuMCwGA1UECgwl0JLQuNC60LjQv9C10LTQuNGOINCS0LjQutC40L/QtdC00LjRjjEWMBQGA1UECwwNZXhhbXBsZSBjb3JwLjEoMCYGA1UEAwwfbWljaGFlbC1vIGNlcnRpZmljYXRlIGF1dGhvcml0eTEkMCIGCSqGSIb3DQEJAQwVbWljaGFlbC1vQGV4YW1wbGUuY29t")
	checkErr(err)

	var (
		subject pkix.RDNSequence
	)

	log.Printf("Src[s]: % x", soExample)

	_, err = asn1.UnmarshalWithParams(soExample, &subject, "utf8")
	checkErr(err)

	sb := bytes.NewBuffer(nil)
	for j := range subject {
		log.Printf("Sub[%d]: %x (%s)", j, subject[j], subject[j])
		// for i := range subject[j] {
		// 	// if field, ok := reflect.TypeOf(subject[j][i]).Elem().FieldByName("Type"); ok {
		// 	// 	log.Printf("sub[%d/%d] field: %#v", j, i, field)
		// 	// }
		// 	// 	// 	// 	// log.Printf("Sub1(Value): %s", subject[j][i].Value)
		// 	// 	// 	// 	subject[j][i].Value = strings.ToLower(subject[j][i].Value.(string))
		// 	// 	// 	// 	// log.Printf("Sub1(Value): %s", subject[j][i].Value)
		// 	// 	log.Printf("Sub[%d/%d]: %q", j, i, subject[j][i].Type)
		// 	// 	switch v := subject[j][i].Value.(type) {
		// 	// 	case []byte:
		// 	// 		log.Printf("Sub[%d/%d]: %x", j, i, v)
		// 	// 	case string:
		// 	// 		log.Printf("Sub[%d/%d]: %s", j, i, v)
		// 	// 	}
		// }
		// log.Printf("Sub[%d]: %x", j, subject[j])

		b, err := asn1.MarshalWithParams(subject[j], "")
		checkErr(err)

		log.Printf("Sub[%d]: % x", j, b)

		if b[9] == 0x13 {
			b[9] = 0x0c
		}

		// // log.Printf("Sub[%d]: %x", j, b)
		_, err = sb.Write(b)
		checkErr(err)
		// if v, ok := sub.(pkix.AttributeTypeAndValue); ok {
		// 	log.Printf("PKIX: %x", v)
		// } else {
		// }
		// log.Printf("Sub.Type: %x", sub.Type)
		// log.Printf("Sub.Value: %x", sub.Value)
	}

	// b, err := asn1.MarshalWithParams(subject, "utf8")
	b, err := asn1.Marshal(subject)
	checkErr(err)
	log.Printf("Dst[s]: % x", b)

	log.Printf("Dst[b]: % x", sb.Bytes())

	cd, err := ioutil.ReadFile("test/stackoverflow-example.pem")
	checkErr(err)

	p, _ := pem.Decode(cd)
	c, err := x509.ParseCertificate(p.Bytes)
	checkErr(err)

	log.Printf("Src[2]: % x", c.RawSubject)

	h, err := subjhash.Subject(c)
	checkErr(err)
	log.Printf("Hash: %s", h)
}
