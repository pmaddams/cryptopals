// 8. Detect AES in ECB mode

package main

import (
	"bufio"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// Subdivide divides a buffer into blocks.
func Subdivide(buf []byte, size int) [][]byte {
	var blocks [][]byte
	for len(buf) >= size {
		// Return pointers, not copies.
		blocks = append(blocks, buf[:size])
		buf = buf[size:]
	}
	return blocks
}

// IdenticalBlocks returns true if any block in the buffer appears more than once.
func IdenticalBlocks(buf []byte, blockSize int) bool {
	m := make(map[string]bool)
	for _, block := range Subdivide(buf, blockSize) {
		s := string(block)
		if m[s] {
			return true
		}
		m[s] = true
	}
	return false
}

// detectECB reads hex-encoded input and prints lines
// that appear to have been encrypted with AES in ECB mode.
func detectECB(in io.Reader) error {
	input := bufio.NewScanner(in)
	for input.Scan() {
		line, err := hex.DecodeString(input.Text())
		if err != nil {
			return err
		}
		if IdenticalBlocks(line, aes.BlockSize) {
			fmt.Println(hex.EncodeToString(line))
		}
	}
	return input.Err()
}

func main() {
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := detectECB(os.Stdin); err != nil {
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
		if err := detectECB(f); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
