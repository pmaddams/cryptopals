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
func unpadAndPrint(in io.Reader, blockSize int) error {
	input := bufio.NewReader(in)
Loop:
	for {
		s, err := input.ReadString('\n')
		switch err {
		case nil:
			s = s[:len(s)-1]
		case io.EOF:
			break Loop
		default:
			return err
		}
		if s, err = strconv.Unquote(`"` + s + `"`); err != nil {
			return err
		}
		buf, err := PKCS7Unpad([]byte(s), blockSize)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		fmt.Println(string(buf))
	}
	return nil
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
		if err := unpadAndPrint(os.Stdin, blockSize); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := unpadAndPrint(f, blockSize); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
