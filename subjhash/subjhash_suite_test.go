package subjhash_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestSubjhash(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Subjhash Suite")
}
