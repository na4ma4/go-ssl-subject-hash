//nolint:unused // testing
package main

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func truncatedHash(b [20]byte, l int) []byte {
	if l < 1 || len(b) < 1 {
		return []byte{}
	}

	result := make([]byte, l)
	for i := 0; i < l; i++ {
		result[l-1-i] = b[i]
	}

	return result
}
