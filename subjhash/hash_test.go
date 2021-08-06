package subjhash_test

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/na4ma4/go-ssl-subject-hash/subjhash"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var empty = subjhash.SubjHash{0, 0, 0, 0}

var _ = Describe("Subjhash/Hash", func() {
	It("throws an error on a nil certificate", func() {
		b, err := subjhash.Subject(nil)
		Expect(err).To(HaveOccurred())
		Expect(b).To(Equal(empty))
	})

	checkCertFileHashFunc := func(filename, hash string) {
		cd, err := ioutil.ReadFile(filename)
		Expect(err).NotTo(HaveOccurred())

		p, _ := pem.Decode(cd)
		c, err := x509.ParseCertificate(p.Bytes)
		Expect(err).NotTo(HaveOccurred())

		h, err := subjhash.Subject(c)
		Expect(err).NotTo(HaveOccurred())
		Expect(h.String()).To(Equal(hash))

		i, err := subjhash.Issuer(c)
		Expect(err).NotTo(HaveOccurred())
		Expect(i.String()).To(Equal(hash))
	}

	checkCertHashFunc := func(filename string) {
		checkCertFileHashFunc(filename, strings.TrimSuffix(filepath.Base(filename), ".0"))
	}

	It("returns correct for the stackoverflow example", func() {
		checkCertFileHashFunc("../test/stackoverflow-example.pem", "5ba4b7de")
	})

	certHashEntryList := []TableEntry{}
	certHashList, err := os.ReadDir("../test/ca-certs/")
	if err != nil {
		Expect(err).NotTo(HaveOccurred())
	}
	for _, certHashFile := range certHashList {
		if certHashFile.IsDir() {
			continue
		}
		certHashEntryList = append(certHashEntryList,
			Entry(certHashFile.Name(), "../test/ca-certs/"+certHashFile.Name()),
		)
	}

	DescribeTable(
		"correctly gets the cert hash",
		checkCertHashFunc,
		// Entry("ca-cert-Amazon_Root_CA_1.pem", "../test/ce5e74ef.0"),
		// Entry("ca-cert-USERTrust_ECC_Certification_Authority.pem", "../test/f30dd6ad.0"),
		// Entry("ca-cert-USERTrust_RSA_Certification_Authority.pem", "../test/fc5a8f99.0"),
		certHashEntryList...,
	)

	Describe("tricky certificates", func() {
		It("[128805a3.0] /C=EE/O=AS Sertifitseerimiskeskus/CN=EE Certification Centre Root CA/emailAddress=pki@sk.ee", func() {
			checkCertHashFunc("../test/ca-certs/128805a3.0")
		})

		It("[5273a94c.0] /C=TR/L=Ankara/O=E-Tu\xC4\x9Fra EBG Bili\xC5\x9Fim Teknolojileri ve Hizmetleri A.\xC5\x9E./OU=E-Tugra Sertifikasyon Merkezi/CN=E-Tugra Certification Authority", func() {
			checkCertHashFunc("../test/ca-certs/5273a94c.0")
		})

		It("[8160b96c.0] /C=HU/L=Budapest/O=Microsec Ltd./CN=Microsec e-Szigno Root CA 2009/emailAddress=info@e-szigno.hu", func() {
			checkCertHashFunc("../test/ca-certs/8160b96c.0")
		})

	})
})
