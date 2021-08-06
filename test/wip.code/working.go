//nolint:deadcode,gosimple,unused
package main

import (
	"bytes"
	"crypto/sha1"
	"log"
)

func working_example() {
	testArray := [][]byte{
		{0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x0C, 0x02, 0x75, 0x73},
		{0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x06, 0x61, 0x6D, 0x61, 0x7A, 0x6F, 0x6E},
		{0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x10, 0x61, 0x6D, 0x61, 0x7A, 0x6F, 0x6E, 0x20, 0x72, 0x6F, 0x6F, 0x74, 0x20, 0x63, 0x61, 0x20, 0x31},
	}

	finalLen := 0
	terms := bytes.NewBuffer(nil)
	for i, v := range testArray {
		finalLen += len(v)
		_, err := terms.Write(v)
		checkErr(err)
		h := sha1.Sum(v)
		n := truncatedHash(h, 4)
		log.Printf("Sum[%d]: (%x) [%x]", i, h, n)
	}

	// finalEncForw := make([]byte, finalLen)
	h := sha1.Sum(terms.Bytes())
	n := truncatedHash(h, 4)
	log.Printf("Sum[FINAL]: (%x) [%x]", h, n)
}
