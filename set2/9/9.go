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

// PKCS7Pad returns a buffer with PKCS#7 padding added.
func PKCS7Pad(buf []byte, blockSize int) []byte {
	n := blockSize - (len(buf) % blockSize)

	return append(buf, bytes.Repeat([]byte{byte(n)}, n)...)
}

// padAndPrint reads lines of text and displays them with PKCS#7 padding added.
func padAndPrint(in io.Reader, blockSize int) {
	input := bufio.NewScanner(in)
	for input.Scan() {
		buf := PKCS7Pad(input.Bytes(), blockSize)
		fmt.Println(strconv.Quote(string(buf)))
	}
	if err := input.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
}

func main() {
	var blockSize int
	flag.IntVar(&blockSize, "b", 20, "block size")
	flag.Parse()
	if blockSize < 1 || blockSize > 255 {
		fmt.Fprintln(os.Stderr, "invalid block size")
		return
	}
	files := flag.Args()
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		padAndPrint(os.Stdin, blockSize)
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		padAndPrint(f, blockSize)
		f.Close()
	}
}
