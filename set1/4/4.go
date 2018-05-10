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

// allXORByteBuffers returns all single-byte XOR products of a buffer.
func allXORByteBuffers(buf []byte) (res [256][]byte) {
	for i := 0; i < len(res); i++ {
		res[i] = make([]byte, len(buf))
		XORByte(res[i], buf, byte(i))
	}
	return
}

// bestXORByteBuffer takes a buffer and a scoring function, and returns
// the message and its score.
func bestXORByteBuffer(buf []byte, scoreFunc func([]byte) float64) ([]byte, float64) {
	var best float64
	var msg []byte

	for _, try := range allXORByteBuffers(buf) {
		if score := scoreFunc(try); score > best {
			best = score
			msg = try
		}
	}
	return msg, best
}

// detectXORByteCipher reads hex-encoded data and prints the string (if any)
// which has been encrypted with single-byte XOR.
func detectXORByteCipher(in io.Reader, scoreFunc func([]byte) float64) {
	input := bufio.NewScanner(in)
	var best float64
	var msg []byte

	for input.Scan() {
		buf, err := hex.DecodeString(input.Text())
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return
		}
		if try, score := bestXORByteBuffer(buf, scoreFunc); score > best {
			best = score
			msg = try
		}
	}
	if err := input.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
	fmt.Print(string(msg))
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
		detectXORByteCipher(os.Stdin, scoreFunc)
		return
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		detectXORByteCipher(f, scoreFunc)
		f.Close()
	}
}
