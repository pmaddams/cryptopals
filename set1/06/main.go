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
	size, err := breakKeySize(buf)
	if err != nil {
		return nil, err
	}
	bufs, err := Transpose(Subdivide(buf, size))
	if err != nil {
		return nil, err
	}
	key := make([]byte, size)

	var wg sync.WaitGroup
	wg.Add(size)
	for i := 0; i < size; i++ {
		// Capture the value of the loop variable.
		go func(i int) {
			key[i] = breakSingleXOR(bufs[i], score)
			wg.Done()
		}(i)
	}
	wg.Wait()

	return key, nil
}

// breakKeySize returns the key size used to encrypt a buffer with repeating XOR.
func breakKeySize(buf []byte) (int, error) {
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
				return 0, errors.New("breakKeySize: nothing found")
			}
			break
		} else if distance < best {
			best = distance
			n = size
		}
	}
	return n, nil
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

// AverageDistance returns the average Hamming distance between adjacent blocks.
func AverageDistance(buf []byte, blockSize int) (float64, error) {
	blocks := Subdivide(buf, blockSize)
	if len(blocks) < 2 {
		return 0, errors.New("AverageDistance: need 2 or more blocks")
	}
	var f float64
	for i := 0; i < len(blocks)-1; i++ {
		n := HammingDistance(blocks[i], blocks[i+1])
		f += float64(n) / float64(blockSize) / float64(len(blocks)-1)
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

// Transpose takes a slice of buffers and returns buffers with the rows and columns swapped.
func Transpose(bufs [][]byte) ([][]byte, error) {
	for i := 0; i < len(bufs); i++ {
		if len(bufs[i]) != len(bufs[0]) {
			return nil, errors.New("Transpose: buffers must have equal length")
		}
	}
	res := make([][]byte, len(bufs[0]))
	for i := 0; i < len(bufs[0]); i++ {
		res[i] = make([]byte, len(bufs))
		for j := 0; j < len(bufs); j++ {
			res[i][j] = bufs[j][i]
		}
	}
	return res, nil
}

// Subdivide divides a buffer into blocks.
func Subdivide(buf []byte, blockSize int) [][]byte {
	var blocks [][]byte
	for len(buf) >= blockSize {
		// Return pointers, not copies.
		blocks = append(blocks, buf[:blockSize])
		buf = buf[blockSize:]
	}
	return blocks
}

// XORSingleByte produces the XOR combination of a buffer with a single byte.
func XORSingleByte(dst, src []byte, b byte) {
	// Panic if dst is smaller than src.
	for i := range src {
		dst[i] = src[i] ^ b
	}
}
