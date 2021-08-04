package subjhash_test

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
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

	DescribeTable(
		"correctly gets the cert hash",
		func(filename string) {
			cd, err := ioutil.ReadFile(filename)
			Expect(err).NotTo(HaveOccurred())

			p, _ := pem.Decode(cd)
			c, err := x509.ParseCertificate(p.Bytes)
			Expect(err).NotTo(HaveOccurred())

			filebase := strings.TrimSuffix(filepath.Base(filename), ".0")

			h, err := subjhash.Subject(c)
			Expect(err).NotTo(HaveOccurred())
			Expect(h.String()).To(Equal(filebase))

			i, err := subjhash.Subject(c)
			Expect(err).NotTo(HaveOccurred())
			Expect(i.String()).To(Equal(filebase))
		},
		Entry("ca-cert-Amazon_Root_CA_1.pem", "../test/ce5e74ef.0"),
		Entry("ca-cert-USERTrust_ECC_Certification_Authority.pem", "../test/f30dd6ad.0"),
		Entry("ca-cert-USERTrust_RSA_Certification_Authority.pem", "../test/fc5a8f99.0"),
	)
})
