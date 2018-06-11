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

// sample is a file with symbol frequencies similar to the expected plaintext.
const sample = "alice.txt"

// scoreBytes must be generated at runtime from the sample file.
var scoreBytes func([]byte) float64

// HammingDistance returns the number of differing bits between two equal-length buffers.
func HammingDistance(b1, b2 []byte) (int, error) {
	if len(b1) != len(b2) {
		return 0, errors.New("HammingDistance: buffer lengths must be equal")
	}
	var res int
	for i := range b1 {
		res += bits.OnesCount8(b1[i] ^ b2[i])
	}
	return res, nil
}

// NormalizedDistance returns the normalized edit distance between pairs of blocks.
func NormalizedDistance(buf []byte, blockSize int) (float64, error) {
	// We need at least 2 blocks.
	if len(buf) < 2*blockSize {
		return 0, errors.New("NormalizedDistance: need at least 2 blocks")
	}
	// Keep the number of pairs to normalize the result, along with the block size.
	numPairs := len(buf)/blockSize - 1

	var res float64
	for len(buf) >= 2*blockSize {
		distance, err := HammingDistance(buf[:blockSize], buf[blockSize:2*blockSize])
		if err != nil {
			return 0, err
		}
		buf = buf[blockSize:]
		res += float64(distance) / float64(numPairs) / float64(blockSize)
	}
	return res, nil
}

// findKeySize returns the probable key size of a buffer encrypted with repeating XOR.
func findKeySize(buf []byte) (int, error) {
	// Guess lower and upper bounds.
	const (
		lower = 2
		upper = 64
	)
	// Set best to an impossibly high value.
	best := float64(8 * len(buf))
	var res int

	for blockSize := lower; blockSize <= upper; blockSize++ {
		// If the block size is too large, stop.
		if distance, err := NormalizedDistance(buf, blockSize); err != nil {
			if res < lower {
				return 0, errors.New("keySize: nothing found")
			}
			break
		} else if distance < best {
			best = distance
			res = blockSize
		}
	}
	return res, nil
}

// SymbolFrequencies reads text and returns a map of UTF-8 symbol frequencies.
func SymbolFrequencies(in io.Reader) (map[rune]float64, error) {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}
	m := make(map[rune]float64)
	runes := []rune(string(buf))
	for _, r := range runes {
		m[r] += 1.0 / float64(len(runes))
	}
	return m, nil
}

// ScoreBytesWithMap takes a buffer and map of symbol frequencies, and returns a score.
func ScoreBytesWithMap(buf []byte, m map[rune]float64) float64 {
	var res float64
	for _, r := range []rune(string(buf)) {
		res += m[r]
	}
	return res
}

// XORSingleByte produces the XOR combination of a buffer with a single byte.
func XORSingleByte(dst, src []byte, b byte) {
	// Panic if dst is smaller than src.
	for i := range src {
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
		if score := scoreBytes(tmp); score > best {
			best = score
			key = b
		}
	}
	return key
}

// Blocks divides a buffer into blocks.
func Blocks(buf []byte, n int) [][]byte {
	var res [][]byte
	for len(buf) >= n {
		// Return pointers, not copies.
		res = append(res, buf[:n])
		buf = buf[n:]
	}
	return res
}

// Lengths returns a slice of integer buffer lengths.
func Lengths(bufs [][]byte) []int {
	var res []int
	for _, buf := range bufs {
		res = append(res, len(buf))
	}
	return res
}

// Transpose takes a slice of equal-length buffers and returns
// a slice of new buffers with the rows and columns swapped.
func Transpose(bufs [][]byte) ([][]byte, error) {
	nums := Lengths(bufs)
	if len(nums) == 0 {
		return nil, errors.New("Transpose: no data")
	}
	for _, n := range nums[1:] {
		if n != nums[0] {
			return nil, errors.New("Transpose: buffers must have equal length")
		}
	}
	res := make([][]byte, nums[0])
	for i := range res {
		res[i] = make([]byte, len(bufs))
		for j := range res[i] {
			res[i][j] = bufs[j][i]
		}
	}
	return res, nil
}

// breakRepeatingXOR returns the key used to encrypt a buffer with repeating XOR.
func breakRepeatingXOR(buf []byte) ([]byte, error) {
	keySize, err := findKeySize(buf)
	if err != nil {
		return nil, err
	}
	blocks, err := Transpose(Blocks(buf, keySize))
	if err != nil {
		return nil, err
	}
	key := make([]byte, keySize)
	var wg sync.WaitGroup

	for i := range blocks {
		wg.Add(1)
		go func(i int) {
			key[i] = breakSingleXOR(blocks[i])
			wg.Done()
		}(i)
	}
	wg.Wait()
	return key, nil
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
	for i := range src {
		dst[i] = src[i] ^ stream.key[stream.pos]
		stream.pos++

		// At the end of the key, reset position.
		if stream.pos == len(stream.key) {
			stream.pos = 0
		}
	}
}

// decryptAndPrint reads base64-encoded ciphertext and prints plaintext.
func decryptAndPrint(in io.Reader) {
	buf, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, in))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	key, err := breakRepeatingXOR(buf)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	stream := NewXORCipher(key)
	stream.XORKeyStream(buf, buf)
	fmt.Print(string(buf))
}

func init() {
	// Generate scoreBytes from the sample file.
	f, err := os.Open(sample)
	defer f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	m, err := SymbolFrequencies(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	scoreBytes = func(buf []byte) float64 {
		return ScoreBytesWithMap(buf, m)
	}
}

func main() {
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		decryptAndPrint(os.Stdin)
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		decryptAndPrint(f)
		f.Close()
	}
}
