// 6. Break repeating-key XOR

package main

import (
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/bits"
	"os"
	"sync"
)

// sample is a file similar to the expected plaintext.
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

// decrypt reads base64-encoded ciphertext and prints plaintext.
func decrypt(in io.Reader, score func([]byte) int) error {
	buf, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, in))
	if err != nil {
		return err
	}
	key, err := breakRepeatingXOR(buf, score)
	if err != nil {
		return err
	}
	stream := NewXORCipher(key)
	stream.XORKeyStream(buf, buf)
	fmt.Print(string(buf))

	return nil
}

// breakRepeatingXOR returns the key used to encrypt a buffer with repeating XOR.
func breakRepeatingXOR(buf []byte, score func([]byte) int) ([]byte, error) {
	size, err := keySize(buf)
	if err != nil {
		return nil, err
	}
	bufs, err := Transpose(Subdivide(buf, size))
	if err != nil {
		return nil, err
	}
	key := make([]byte, size)

	var wg sync.WaitGroup
	for i := range bufs {
		wg.Add(1)
		// Capture the value of the loop variable.
		go func(i int) {
			key[i] = breakSingleXOR(bufs[i], score)
			wg.Done()
		}(i)
	}
	wg.Wait()

	return key, nil
}

// keySize returns the probable key size of a buffer encrypted with repeating XOR.
func keySize(buf []byte) (int, error) {
	// Guess lower and upper bounds.
	const (
		lower = 2
		upper = 64
	)
	var n int
	best := float64(8 * len(buf))
	for size := lower; size <= upper; size++ {
		// If the block size is too large, stop.
		if distance, err := AverageDistance(buf, size); err != nil {
			if n < lower {
				return 0, errors.New("keySize: nothing found")
			}
			break
		} else if distance < best {
			best = distance
			n = size
		}
	}
	return n, nil
}

// AverageDistance returns the average Hamming distance between adjacent blocks.
func AverageDistance(buf []byte, size int) (float64, error) {
	blocks := Subdivide(buf, size)
	if len(blocks) < 2 {
		return 0, errors.New("AverageDistance: need 2 or more blocks")
	}
	var f float64
	for i := 0; i < len(blocks)-1; i++ {
		n := HammingDistance(blocks[i], blocks[i+1])
		f += float64(n) / float64(size) / float64(len(blocks)-1)
	}
	return f, nil
}

// HammingDistance returns the number of differing bits between two buffers.
func HammingDistance(b1, b2 []byte) int {
	var short, long []byte
	if len(b1) < len(b2) {
		short, long = b1, b2
	} else {
		short, long = b2, b1
	}
	var n int
	for i := range short {
		n += bits.OnesCount8(short[i] ^ long[i])
	}
	n += 8 * (len(long) - len(short))

	return n
}

// Transpose takes a slice of blocks and returns buffers swapping the rows and columns.
func Transpose(blocks [][]byte) ([][]byte, error) {
	for i := 0; i < len(blocks); i++ {
		if len(blocks[i]) != len(blocks[0]) {
			return nil, errors.New("Transpose: blocks must have equal length")
		}
	}
	bufs := make([][]byte, len(blocks[0]))
	for i := 0; i < len(blocks[0]); i++ {
		bufs[i] = make([]byte, len(blocks))
		for j := 0; j < len(blocks); j++ {
			bufs[i][j] = blocks[j][i]
		}
	}
	return bufs, nil
}

// Subdivide divides a buffer into blocks.
func Subdivide(buf []byte, size int) [][]byte {
	var blocks [][]byte
	for len(buf) >= size {
		// Return pointers, not copies.
		blocks = append(blocks, buf[:size])
		buf = buf[size:]
	}
	return blocks
}

// breakSingleXOR returns the key used to encrypt a buffer with single-byte XOR.
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

// xorCipher represents a repeating XOR stream cipher.
type xorCipher struct {
	key []byte
	pos int
}

// NewXORCipher creates a new repeating XOR cipher.
func NewXORCipher(key []byte) cipher.Stream {
	return &xorCipher{key: key}
}

// XORKeyStream encrypts a buffer with repeating XOR.
func (x *xorCipher) XORKeyStream(dst, src []byte) {
	// Panic if dst is smaller than src.
	for i := range src {
		dst[i] = src[i] ^ x.key[x.pos]
		x.pos++
		if x.pos == len(x.key) {
			x.pos = 0
		}
	}
}
