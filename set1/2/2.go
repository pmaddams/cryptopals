package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// min returns the smaller of two integers.
func min(n, m int) int {
	if n < m {
		return n
	}
	return m
}

// XORBytes produces the XOR combination of two buffers.
func XORBytes(dst, b1, b2 []byte) int {
	n := min(len(b1), len(b2))
	for i := 0; i < n; i++ {
		dst[i] = b1[i] ^ b2[i]
	}
	return n
}

// xorTwoLines reads two hex-encoded lines and prints their XOR combination.
func xorTwoLines(in io.Reader) error {
	var s1, s2 string
	if _, err := fmt.Fscanln(in, &s1); err != nil {
		return err
	} else if _, err = fmt.Fscanln(in, &s2); err != nil {
		return err
	}
	b1, err := hex.DecodeString(s1)
	if err != nil {
		return err
	}
	b2, err := hex.DecodeString(s2)
	if err != nil {
		return err
	}
	// Write the data in place to the shorter buffer.
	var dst []byte
	if len(b1) < len(b2) {
		dst = b1
	} else {
		dst = b2
	}
	XORBytes(dst, b1, b2)
	fmt.Printf("%x\n", dst)

	return nil
}

func main() {
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := xorTwoLines(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := xorTwoLines(f); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
