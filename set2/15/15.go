package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
)

// AES always has a block size of 128 bits (16 bytes).
const aesBlockSize = 16

// PKCS7Pad returns a buffer with PKCS#7 padding added.
func PKCS7Pad(buf []byte, blockSize int) []byte {
	n := blockSize - (len(buf) % blockSize)

	return append(buf, bytes.Repeat([]byte{byte(n)}, n)...)
}

// PKCS7Unpad returns a buffer with PKCS#7 padding removed.
func PKCS7Unpad(buf []byte, blockSize int) ([]byte, error) {
	if len(buf) < blockSize {
		return nil, errors.New("PKCS7Unpad: invalid padding")
	}
	// Examine the value of the last byte.
	b := buf[len(buf)-1]
	if int(b) == 0 || int(b) > blockSize ||
		!bytes.Equal(bytes.Repeat([]byte{b}, int(b)), buf[len(buf)-int(b):]) {
		return nil, errors.New("PKCS7Unpad: invalid padding")
	}
	return buf[:len(buf)-int(b)], nil
}

// unpadAndPrint prints lines of PKCS#7 padded input with padding removed.
func unpadAndPrint(in io.Reader, blockSize int) {
	input := bufio.NewReader(in)
	for {
		s, err := input.ReadString('\n')
		if err == nil {
			s = s[:len(s)-1]
		} else if err == io.EOF {
			break
		} else {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		s, err = strconv.Unquote(`"` + s + `"`)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		buf, err := PKCS7Unpad([]byte(s), blockSize)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		fmt.Println(string(buf))
	}
}

func main() {
	var blockSize int
	flag.IntVar(&blockSize, "b", aesBlockSize, "block size")
	flag.Parse()
	if blockSize < 1 || blockSize > 255 {
		fmt.Fprintln(os.Stderr, "invalid block size")
		return
	}
	files := flag.Args()
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		unpadAndPrint(os.Stdin, blockSize)
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		unpadAndPrint(f, blockSize)
		f.Close()
	}
}
