package main

import "errors"

// Xor returns the XOR combination of two equal-length buffers.
func Xor(b1, b2 []byte) ([]byte, error) {
	if len(b1) != len(b2) {
		return nil, errors.New("buffers must have equal length")
	}
	res := make([]byte, len(b1))
	for i, _ := range b1 {
		res[i] = b1[i] ^ b2[i]
	}
	return res, nil
}

func main() {
}
