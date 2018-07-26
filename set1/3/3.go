package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// sample is a file similar to the expected plaintext.
const sample = "alice.txt"

// Symbols reads text and returns a map of UTF-8 symbol counts.
func Symbols(in io.Reader) (map[rune]int, error) {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}
	m := make(map[rune]int)
	for _, r := range string(buf) {
		m[r]++
	}
	return m, nil
}

// Score takes a buffer and map of symbol counts, and returns a score.
func Score(buf []byte, m map[rune]int) int {
	var n int
	for _, r := range string(buf) {
		n += m[r]
	}
	return n
}

// scoreFunc takes a sample file and returns a score function.
func scoreFunc(name string) (func([]byte) int, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m, err := Symbols(f)
	if err != nil {
		return nil, err
	}
	return func(buf []byte) int {
		return Score(buf, m)
	}, nil
}

// XORSingleByte produces the XOR combination of a buffer with a single byte.
func XORSingleByte(dst, src []byte, b byte) {
	// Panic if dst is smaller than src.
	for i := range src {
		dst[i] = src[i] ^ b
	}
}

// breakSingleXOR takes a buffer and score function, and returns the single-byte XOR key.
func breakSingleXOR(buf []byte, score func([]byte) int) byte {
	// Don't modify the original data.
	tmp := make([]byte, len(buf))
	var (
		best int
		key  byte
	)
	// Use an integer as the loop variable to avoid overflow.
	for i := 0; i <= 0xff; i++ {
		XORSingleByte(tmp, buf, byte(i))
		if n := score(tmp); n > best {
			best = n
			key = byte(i)
		}
	}
	return key
}

// decryptSingleXOR reads hex-encoded ciphertext and prints plaintext.
func decryptSingleXOR(in io.Reader, score func([]byte) int) error {
	input := bufio.NewScanner(in)
	var buf []byte
	for input.Scan() {
		line, err := hex.DecodeString(input.Text())
		if err != nil {
			return err
		}
		buf = append(buf, line...)
	}
	if err := input.Err(); err != nil {
		return err
	}
	key := breakSingleXOR(buf, score)
	XORSingleByte(buf, buf, key)
	fmt.Println(string(buf))

	return nil
}

func main() {
	score, err := scoreFunc(sample)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := decryptSingleXOR(os.Stdin, score); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := decryptSingleXOR(f, score); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
