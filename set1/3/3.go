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

// scoreBuf must be generated at runtime from the sample file.
var scoreBuf func([]byte) float64

// SymbolFrequencies reads text and returns a map of UTF-8 symbol frequencies.
func SymbolFrequencies(in io.Reader) (map[rune]float64, error) {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}
	runes := []rune(string(buf))
	m := make(map[rune]float64)

	for _, r := range runes {
		m[r] += 1.0 / float64(len(runes))
	}
	return m, nil
}

// ScoreBufWithMap takes a buffer and map of symbol frequencies, and returns a score.
func ScoreBufWithMap(buf []byte, m map[rune]float64) (res float64) {
	runes := []rune(string(buf))
	for _, r := range runes {
		f, _ := m[r]
		res += f
	}
	return
}

// XORSingleByte produces the XOR combination of a buffer with a single byte.
func XORSingleByte(dst, src []byte, b byte) {
	// Panic if dst is smaller than src.
	for i := 0; i < len(src); i++ {
		dst[i] = src[i] ^ b
	}
}

// breakSingleXOR returns the key used to encrypt a buffer with single byte XOR.
func breakSingleXOR(buf []byte) byte {
	// Don't stomp on the original data.
	tmp := make([]byte, len(buf))

	var best float64
	var key byte

	// Use an integer as the loop variable to avoid overflow.
	for i := 0; i < 256; i++ {
		b := byte(i)
		XORSingleByte(tmp, buf, b)
		if score := scoreBuf(tmp); score > best {
			best = score
			key = b
		}
	}
	return key
}

// decryptAndPrint reads hex-encoded ciphertext and prints plaintext.
func decryptAndPrint(in io.Reader) {
	input := bufio.NewScanner(in)
	var buf []byte
	for input.Scan() {
		line, err := hex.DecodeString(input.Text())
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return
		}
		buf = append(buf, line...)
	}
	if err := input.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	key := breakSingleXOR(buf)
	XORSingleByte(buf, buf, key)
	fmt.Println(string(buf))
}

func init() {
	// Generate scoreBuf from the sample file.
	f, err := os.Open(sample)
	defer f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	m, err := SymbolFrequencies(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	scoreBuf = func(buf []byte) float64 {
		return ScoreBufWithMap(buf, m)
	}
}

func main() {
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		decryptAndPrint(os.Stdin)
		return
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		decryptAndPrint(f)
		f.Close()
	}
}
