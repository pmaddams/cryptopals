package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"errors"
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
	return dup(buf)[:len(buf)-int(b)], nil
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
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		s, err = strconv.Unquote(`"` + s + `"`)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		buf, err := PKCS7Unpad([]byte(s), blockSize)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		fmt.Println(string(buf))
	}
}

func main() {
	var blockSize int
	flag.IntVar(&blockSize, "b", aes.BlockSize, "block size")
	flag.Parse()
	if blockSize <= 0 || blockSize > 0xff {
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
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		unpadAndPrint(f, blockSize)
		f.Close()
	}
}
