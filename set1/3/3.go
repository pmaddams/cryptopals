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
func XORByte(out, buf []byte, b byte) int {
	n := len(buf)
	for i := 0; i < n; i++ {
		out[i] = buf[i] ^ b
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
// the message and single-byte key corresponding to the highest score.
func bestXORByteBuffer(buf []byte, scoreFunc func([]byte) float64) (msg []byte, key byte) {
	var best float64
	for i, try := range allXORByteBuffers(buf) {
		if score := scoreFunc(try); score > best {
			best = score
			msg = try
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
		buf, err := hex.DecodeString(input.Text())
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return
		}
		msg, key := bestXORByteBuffer(buf, scoreFunc)
		fmt.Printf("MESSAGE: %s\nKEY: 0x%x\n", msg, key)
	}
	if err := input.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
	return
}

func main() {
	// Generate a scoring function from a sample file.
	scoreFunc := func() func([]byte) float64 {
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
		return func(buf []byte) float64 {
			return Score(m, buf)
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
