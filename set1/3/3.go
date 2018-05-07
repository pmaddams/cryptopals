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

// Symbols reads text and returns a map of UTF-8 symbol frequencies.
func Symbols(in io.Reader) (map[rune]float64, error) {
	bytes, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}
	runes := []rune(string(bytes))
	m := make(map[rune]float64)

	for _, r := range runes {
		m[r] += 1.0 / float64(len(runes))
	}
	return m, nil
}

// Score adds up the frequencies for UTF-8 symbols encoded in the buffer.
func Score(m map[rune]float64, bytes []byte) (res float64) {
	runes := []rune(string(bytes))
	for _, r := range runes {
		f, _ := m[r]
		res += f
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
func breakXORByteCipher(in io.Reader, scoreFunc func([]byte) float64) {
	input := bufio.NewScanner(in)
	for input.Scan() {
		bytes, err := hex.DecodeString(input.Text())
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return
		}
		msg, key := bestXORByteBuffer(bytes, scoreFunc)
		fmt.Printf("MESSAGE: %s\nKEY: 0x%x\n", msg, key)
	}
	if err := input.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
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
		var m map[rune]float64
		m, err = Symbols(f)
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
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		breakXORByteCipher(f, scoreFunc)
		f.Close()
	}
}
