// 3. Single-byte XOR cipher

package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const sample = "alice.txt"

func main() {
	f, err := os.Open(sample)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	score, err := ScoreFunc(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	f.Close()

	files := os.Args[1:]
	if len(files) == 0 {
		if err := decrypt(os.Stdin, score); err != nil {
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
		if err := decrypt(f, score); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}

// decrypt reads hex-encoded ciphertext and prints plaintext.
func decrypt(in io.Reader, score func([]byte) int) error {
	var buf []byte
	input := bufio.NewScanner(in)
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
	XORSingleByte(buf, buf, breakSingleXOR(buf, score))
	fmt.Println(string(buf))

	return nil
}

// breakSingleXOR takes a buffer and scoring function, and returns the probable key.
func breakSingleXOR(buf []byte, score func([]byte) int) byte {
	var (
		key  byte
		best int
	)
	tmp := make([]byte, len(buf))
	for i := 0; i <= 0xff; i++ {
		XORSingleByte(tmp, buf, byte(i))
		if n := score(tmp); n > best {
			best = n
			key = byte(i)
		}
	}
	return key
}

// ScoreFunc reads sample text and returns a scoring function.
func ScoreFunc(in io.Reader) (func([]byte) int, error) {
	m, err := SymbolCounts(in)
	if err != nil {
		return nil, err
	}
	return func(buf []byte) int {
		var n int
		for _, r := range string(buf) {
			n += m[r]
		}
		return n
	}, nil
}

// SymbolCounts reads sample text and returns a map of UTF-8 symbol counts.
func SymbolCounts(in io.Reader) (map[rune]int, error) {
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

// XORSingleByte produces the XOR combination of a buffer with a single byte.
func XORSingleByte(dst, src []byte, b byte) {
	// Panic if dst is smaller than src.
	for i := range src {
		dst[i] = src[i] ^ b
	}
}
