// 9. Implement PKCS#7 padding

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
)

// dup returns a copy of a buffer.
func dup(buf []byte) []byte {
	return append([]byte{}, buf...)
}

// PKCS7Pad returns a buffer with PKCS#7 padding added.
func PKCS7Pad(buf []byte, blockSize int) []byte {
	if blockSize < 0 || blockSize > 0xff {
		panic("PKCS7Pad: invalid block size")
	}
	// Find the number (and value) of padding bytes.
	n := blockSize - (len(buf) % blockSize)

	return append(dup(buf), bytes.Repeat([]byte{byte(n)}, n)...)
}

// printPKCS7 reads lines of text and displays them with PKCS#7 padding added.
func printPKCS7(in io.Reader, blockSize int) error {
	input := bufio.NewScanner(in)
	for input.Scan() {
		buf := PKCS7Pad(input.Bytes(), blockSize)
		fmt.Println(strconv.Quote(string(buf)))
	}
	return input.Err()
}

func main() {
	var blockSize int
	flag.IntVar(&blockSize, "b", 20, "block size")
	flag.Parse()
	if blockSize <= 0 || blockSize > 0xff {
		fmt.Fprintln(os.Stderr, "invalid block size")
		return
	}
	files := flag.Args()
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := printPKCS7(os.Stdin, blockSize); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := printPKCS7(f, blockSize); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
