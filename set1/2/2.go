package main

import (
	"bufio"
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
func xorTwoLines(r io.Reader) {
	input := bufio.NewScanner(r)
	var b1, b2, out []byte
	var err error

	// Read two lines and exit if either one is empty or invalid.
	if !input.Scan() || len(input.Text()) == 0 {
		return
	}
	if b1, err = hex.DecodeString(input.Text()); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	if !input.Scan() || len(input.Text()) == 0 {
		return
	}
	if b2, err = hex.DecodeString(input.Text()); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}

	// Write the data in place to the shorter buffer.
	if len(b1) < len(b2) {
		out = b1
	} else {
		out = b2
	}
	XORBytes(out, b1, b2)
	fmt.Printf("%x\n", out)
}

func main() {
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		xorTwoLines(os.Stdin)
		return
	}
	for _, arg := range files {
		f, err := os.Open(arg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		xorTwoLines(f)
		f.Close()
	}
}
