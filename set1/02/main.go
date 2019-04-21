// 2. Fixed XOR

package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	files := os.Args[1:]
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

// xorLines reads two hex-encoded lines and prints their XOR combination.
func xorLines(in io.Reader) error {
	b1, err := readHex(in)
	if err != nil {
		return err
	}
	b2, err := readHex(in)
	if err != nil {
		return err
	}
	n := XORBytes(b1, b1, b2)
	fmt.Printf("%x\n", b1[:n])

	return nil
}

// readHex reads a hex-encoded line and returns a buffer.
func readHex(in io.Reader) ([]byte, error) {
	var buf []byte
	if _, err := fmt.Fscanf(in, "%x\n", &buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// XORBytes produces the XOR combination of two buffers.
func XORBytes(dst, b1, b2 []byte) int {
	n := min(len(b1), len(b2))
	for i := 0; i < n; i++ {
		dst[i] = b1[i] ^ b2[i]
	}
	return n
}

// min returns the smaller of two integers.
func min(n, m int) int {
	if n < m {
		return n
	}
	return m
}
