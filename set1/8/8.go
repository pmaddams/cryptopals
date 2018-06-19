package main

import (
	"bufio"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// Blocks divides a buffer into blocks.
func Blocks(buf []byte, n int) [][]byte {
	var res [][]byte
	for len(buf) >= n {
		// Return pointers, not copies.
		res = append(res, buf[:n])
		buf = buf[n:]
	}
	return res
}

// IdenticalBlocks returns true if any block in the buffer appears more than once.
func IdenticalBlocks(buf []byte, blockSize int) bool {
	m := make(map[string]bool)
	for _, block := range Blocks(buf, blockSize) {
		s := string(block)
		if m[s] {
			return true
		}
		m[s] = true
	}
	return false
}

// detectAndPrintECB reads hex-encoded input and prints lines
// that appear to have been encrypted with AES in ECB mode.
func detectAndPrintECB(in io.Reader) {
	input := bufio.NewScanner(in)
	for input.Scan() {
		line, err := hex.DecodeString(input.Text())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if IdenticalBlocks(line, aes.BlockSize) {
			fmt.Println(hex.EncodeToString(line))
		}
	}
	if err := input.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

func main() {
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		detectAndPrintECB(os.Stdin)
		return
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		detectAndPrintECB(f)
		f.Close()
	}
}
