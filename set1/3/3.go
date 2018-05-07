package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const sample = "alice.txt"

// Classify decides if a byte is a letter, a space, or neither.
func Classify(b byte) byte {
	switch {
	case b >= 'A' && b <= 'Z':
		return b
	case b >= 'a' && b <= 'z':
		return b - 'a' + 'A'
	case b == ' ' || b == '\n':
		return ' '
	default:
		return 0
	}
}

// LetterFrequency reads text and returns a map of letter frequencies.
func LetterFrequency(r io.Reader) (map[byte]float64, error) {
	bytes, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	m := make(map[byte]float64)

	// A point represents a unit fraction of the data.
	point := float64(1/len(bytes))
	for _, b := range bytes {
		m[Classify(b)] += point
	}
	return m, nil
}

// Score adds up the points for letters and spaces in the buffer.
func Score(m map[byte]float64, bytes []byte) (res float64) {
	for _, b := range bytes {
		if k := Classify(b); k != 0 {
			f, _ := m[k]
			res += f
		}
	}
	return
}

// XORByte produces the XOR combination of a buffer with a single byte.
func XORByte(dst, bytes []byte, b byte) int {
	n := len(bytes)
	for i := 0; i < n; i++ {
		dst[i] = bytes[i] ^ b
	}
	return n
}

// allXORByteBuffers returns all single-byte XOR products of a buffer.
func allXORByteBuffers(bytes []byte) (res [256][]byte) {
	for i := 0; i < len(res); i++ {
		res[i] = make([]byte, len(bytes))
		XORByte(res[i], bytes, byte(i))
	}
	return
}

// bestXORByteBuffer takes a buffer and a scoring function, and returns
// the message and single-byte key corresponding to the highest score.
func bestXORByteBuffer(bytes []byte, scoreFunc func([]byte) float64) (msg []byte, key byte) {
	var best float64
	for i, buf := range allXORByteBuffers(bytes) {
		if score := scoreFunc(buf); score > best {
			best = score
			msg = buf
			key = byte(i)
		}
	}
	return
}

// breakXORByteCipher reads hex-encoded, encrypted data and breaks the cipher
// using a scoring function, printing the message and key to standard output.
func breakXORByteCipher(r io.Reader, scoreFunc func([]byte) float64) {
	dec := hex.NewDecoder(r)
	bytes, err := ioutil.ReadAll(dec)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	msg, key := bestXORByteBuffer(bytes, scoreFunc)
	fmt.Printf("MESSAGE: %s\nKEY: %v\n", msg, key)
	return
}

func main() {
	// Generate a scoring function from a sample file.
	scoreFunc := func() func(bytes []byte) float64 {
		var f *os.File
		var err error

		f, err = os.Open(sample)
		defer f.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		var m map[byte]float64
		m, err = LetterFrequency(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}

		return func(bytes []byte) float64 {
			return Score(m, bytes)
		}
	}()

	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		breakXORByteCipher(os.Stdin, scoreFunc)
		return
	}
	for _, arg := range files {
		f, err := os.Open(arg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		breakXORByteCipher(f, scoreFunc)
		return
	}
}
