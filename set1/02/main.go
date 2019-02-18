// 2. Fixed XOR

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

// xorLines reads two hex-encoded lines and prints their XOR combination.
func xorLines(in io.Reader) error {
	var s string
	if _, err := fmt.Fscanln(in, &s); err != nil {
		return err
	}
	b1, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if _, err := fmt.Fscanln(in, &s); err != nil {
		return err
	}
	b2, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	n := XORBytes(b1, b1, b2)
	fmt.Printf("%x\n", b1[:n])

	return nil
}

func main() {
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := xorLines(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := xorLines(f); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
