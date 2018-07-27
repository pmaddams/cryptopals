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

// EditDistance returns the number of differing bits between two buffers.
func EditDistance(b1, b2 []byte) int {
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

// Blocks divides a buffer into blocks.
func Blocks(buf []byte, blockSize int) [][]byte {
	var bufs [][]byte
	for len(buf) >= blockSize {
		// Return pointers, not copies.
		bufs = append(bufs, buf[:blockSize])
		buf = buf[blockSize:]
	}
	return bufs
}

// NormalizedDistance returns the normalized edit distance between pairs of blocks.
func NormalizedDistance(buf []byte, blockSize int) (float64, error) {
	bufs := Blocks(buf, blockSize)
	if len(bufs) < 2 {
		return 0, errors.New("NormalizedDistance: need 2 or more blocks")
	}
	var f float64
	for i := 0; i < len(bufs)-1; i++ {
		n := EditDistance(bufs[i], bufs[i+1])
		f += float64(n) / float64(blockSize) / float64(len(bufs)-1)
	}
	return f, nil
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
	for blockSize := lower; blockSize <= upper; blockSize++ {
		// If the block size is too large, stop.
		if distance, err := NormalizedDistance(buf, blockSize); err != nil {
			if n < lower {
				return 0, errors.New("keySize: nothing found")
			}
			break
		} else if distance < best {
			best = distance
			n = blockSize
		}
	}
	return n, nil
}

// Symbols reads text and returns a map of UTF-8 symbol counts.
func Symbols(in io.Reader) (map[rune]int, error) {
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

// Score takes a buffer and map of symbol counts, and returns a score.
func Score(buf []byte, m map[rune]int) int {
	var n int
	for _, r := range string(buf) {
		n += m[r]
	}
	return n
}

// scoreFunc takes a sample file and returns a score function.
func scoreFunc(file string) (func([]byte) int, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m, err := Symbols(f)
	if err != nil {
		return nil, err
	}
	return func(buf []byte) int {
		return Score(buf, m)
	}, nil
}

// XORSingleByte produces the XOR combination of a buffer with a single byte.
func XORSingleByte(dst, src []byte, b byte) {
	// Panic if dst is smaller than src.
	for i := range src {
		dst[i] = src[i] ^ b
	}
}

// breakSingleXOR takes a buffer and score function, and returns the single-byte XOR key.
func breakSingleXOR(buf []byte, score func([]byte) int) byte {
	// Don't modify the original data.
	tmp := make([]byte, len(buf))
	var (
		key  byte
		best int
	)
	// Use an integer as the loop variable to avoid overflow.
	for i := 0; i <= 0xff; i++ {
		XORSingleByte(tmp, buf, byte(i))
		if n := score(tmp); n > best {
			best = n
			key = byte(i)
		}
	}
	return key
}

// Lengths returns a slice of integer buffer lengths.
func Lengths(bufs [][]byte) []int {
	var nums []int
	for _, buf := range bufs {
		nums = append(nums, len(buf))
	}
	return nums
}

// Transpose takes equal-length buffers and returns them with the rows and columns swapped.
func Transpose(bufs [][]byte) ([][]byte, error) {
	nums := Lengths(bufs)
	if len(nums) == 0 {
		return nil, errors.New("Transpose: no data")
	}
	n := nums[0]
	for i := range nums[1:] {
		if nums[i] != n {
			return nil, errors.New("Transpose: buffers must have equal lengths")
		}
	}
	res := make([][]byte, n)
	for i := range res {
		res[i] = make([]byte, len(bufs))
		for j := range res[i] {
			res[i][j] = bufs[j][i]
		}
	}
	return res, nil
}

// breakXOR returns the key used to encrypt a buffer with repeating XOR.
func breakXOR(buf []byte, score func([]byte) int) ([]byte, error) {
	blockSize, err := keySize(buf)
	if err != nil {
		return nil, err
	}
	bufs, err := Transpose(Blocks(buf, blockSize))
	if err != nil {
		return nil, err
	}
	key := make([]byte, blockSize)

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

// decryptXOR reads base64-encoded ciphertext and prints plaintext.
func decryptXOR(in io.Reader, score func([]byte) int) error {
	buf, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, in))
	if err != nil {
		return err
	}
	key, err := breakXOR(buf, score)
	if err != nil {
		return err
	}
	stream := NewXORCipher(key)
	stream.XORKeyStream(buf, buf)
	fmt.Print(string(buf))

	return nil
}

func main() {
	score, err := scoreFunc(sample)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := decryptXOR(os.Stdin, score); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := decryptXOR(f, score); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
