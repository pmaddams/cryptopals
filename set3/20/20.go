package main

import (
	"crypto/cipher"
	_ "encoding/base64"
	_ "errors"
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

// XORSingleByte produces the XOR combination of a buffer with a single byte.
func XORSingleByte(dst, src []byte, b byte) {
	// Panic if dst is smaller than src.
	for i := 0; i < len(src); i++ {
		dst[i] = src[i] ^ b
	}
}

// breakSingleXOR returns the key used to encrypt a buffer with single byte XOR.
func breakSingleXOR(buf []byte, scoreFunc func([]byte) float64) byte {
	// Don't stomp on the original data.
	tmp := make([]byte, len(buf))

	var best float64
	var key byte

	// Use an integer as the loop variable to avoid overflow.
	for i := 0; i < 256; i++ {
		b := byte(i)
		XORSingleByte(tmp, buf, b)
		if score := scoreFunc(tmp); score > best {
			best = score
			key = b
		}
	}
	return key
}

// xorCipher is a repeating XOR stream cipher.
type xorCipher struct {
	key []byte
	pos int
}

// NewXORCipher creates a new repeating XOR cipher.
func NewXORCipher(key []byte) cipher.Stream {
	return &xorCipher{key, 0}
}

// XORKeyStream encrypts a buffer with repeating XOR.
func (stream *xorCipher) XORKeyStream(dst, src []byte) {
	// Panic if dst is smaller than src.
	for i := 0; i < len(src); i++ {
		dst[i] = src[i] ^ stream.key[stream.pos]
		stream.pos++

		// At the end of the key, reset position.
		if stream.pos >= len(stream.key) {
			stream.pos = 0
		}
	}
}

func init() {
	// Generate scoreFunc from the sample file.
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
	scoreFunc = func(buf []byte) float64 {
		return Score(m, buf)
	}
}

func main() {
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		f.Close()
	}
}
