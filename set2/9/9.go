package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
)

// PKCS7Pad returns a buffer with PKCS#7 padding added.
func PKCS7Pad(buf []byte, blockSize int) []byte {
	var n int

	// If the buffer length is a multiple of the block size,
	// add a number of padding bytes equal to the block size.
	if rem := len(buf) % blockSize; rem == 0 {
		n = blockSize
	} else {
		n = blockSize - rem
	}
	for i := 0; i < n; i++ {
		buf = append(buf, byte(n))
	}
	return buf
}

// FormatBytes converts a buffer to a string with non-printing characters hex-encoded.
func FormatBytes(buf []byte) string {
	var out []rune
	for _, r := range []rune(string(buf)) {
		if strconv.IsPrint(r) {
			out = append(out, r)
		} else {
			out = append(out, []rune(fmt.Sprintf("\\x%02x", r))...)
		}
	}
	return string(out)
}

// padAndPrint reads lines of text and displays them with PKCS#7 padding added.
func padAndPrint(in io.Reader, blockSize int) {
	input := bufio.NewScanner(in)
	for input.Scan() {
		fmt.Println(FormatBytes(PKCS7Pad(input.Bytes(), blockSize)))
	}
	if err := input.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
}

var blockSize int

func main() {
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
