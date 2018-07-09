package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// sample is a file with symbol frequencies similar to the expected plaintext.
const sample = "alice.txt"

// scoreBytes must be generated at runtime from the sample file.
var scoreBytes func([]byte) float64

// SymbolFrequencies reads text and returns a map of UTF-8 symbol frequencies.
func SymbolFrequencies(in io.Reader) (map[rune]float64, error) {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}
	m := make(map[rune]float64)
	runes := []rune(string(buf))
	for _, r := range runes {
		m[r] += 1.0 / float64(len(runes))
	}
	return m, nil
}

// ScoreBytesWithMap takes a buffer and map of symbol frequencies, and returns a score.
func ScoreBytesWithMap(buf []byte, m map[rune]float64) float64 {
	var f float64
	for _, r := range []rune(string(buf)) {
		f += m[r]
	}
	return f
}

// XORSingleByte produces the XOR combination of a buffer with a single byte.
func XORSingleByte(dst, src []byte, b byte) {
	// Panic if dst is smaller than src.
	for i := range src {
		dst[i] = src[i] ^ b
	}
}

// breakSingleXOR returns the key used to encrypt a buffer with single byte XOR.
func breakSingleXOR(buf []byte) byte {
	// Don't stomp on the original data.
	tmp := make([]byte, len(buf))
	var (
		b    byte
		best float64
	)
	// Use an integer as the loop variable to avoid overflow.
	for i := 0; i <= 0xff; i++ {
		XORSingleByte(tmp, buf, byte(i))
		if score := scoreBytes(tmp); score > best {
			best = score
			b = byte(i)
		}
	}
	return b
}

// decryptAndPrint reads hex-encoded ciphertext and prints plaintext.
func decryptAndPrint(in io.Reader) error {
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
	key := breakSingleXOR(buf)
	XORSingleByte(buf, buf, key)
	fmt.Println(string(buf))

	return nil
}

func init() {
	// Generate scoreBytes from the sample file.
	f, err := os.Open(sample)
	defer f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	m, err := SymbolFrequencies(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	scoreBytes = func(buf []byte) float64 {
		return ScoreBytesWithMap(buf, m)
	}
}

func main() {
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := decryptAndPrint(os.Stdin); err != nil {
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
		if err := decryptAndPrint(f); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
