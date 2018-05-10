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

// scoreFunc must be generated at runtime from the sample file.
var scoreFunc func([]byte) float64

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

// Score adds up the frequencies for UTF-8 symbols encoded in the buffer.
func Score(m map[rune]float64, buf []byte) (res float64) {
	runes := []rune(string(buf))
	for _, r := range runes {
		f, _ := m[r]
		res += f
	}
	return
}

// XORByte produces the XOR combination of a buffer with a single byte.
func XORByte(dst, buf []byte, b byte) int {
	n := len(buf)
	for i := 0; i < n; i++ {
		dst[i] = buf[i] ^ b
	}
	return n
}

// breakXORByte returns the key used to encrypt a buffer with single byte XOR.
func breakXORByte(buf []byte, scoreFunc func([]byte) float64) byte {
	// Don't stomp on the original data.
	tmp := make([]byte, len(buf))

	var best float64
	var key byte

	// Use an integer as the loop variable to avoid overflow.
	for i := 0; i < 256; i++ {
		b := byte(i)
		XORByte(tmp, buf, b)
		if score := scoreFunc(tmp); score > best {
			best = score
			key = b
		}
	}
	return key
}

// decryptAndPrint reads hex-encoded ciphertext and prints plaintext.
func decryptAndPrint(in io.Reader, scoreFunc func([]byte) float64) {
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
	key := breakXORByte(buf, scoreFunc)
	XORByte(buf, buf, key)
	fmt.Println(string(buf))
}

func init() {
	// Generate scoreFunc from the sample file.
	var f *os.File
	var err error
	f, err = os.Open(sample)
	defer f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	// The frequency map is retained in a closure.
	var m map[rune]float64
	m, err = SymbolFrequencies(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	scoreFunc = func(buf []byte) float64 {
		return Score(m, buf)
	}
}

func main() {
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		decryptAndPrint(os.Stdin, scoreFunc)
		return
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		decryptAndPrint(f, scoreFunc)
		f.Close()
	}
}
