package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/bits"
	"os"
)

// sample is a file with symbol frequencies similar to the expected plaintext.
const sample = "alice.txt"

// scoreFunc must be generated at runtime from the sample file.
var scoreFunc func([]byte) float64

// HammingDistance returns the number of differing bits between two equal-length buffers.
func HammingDistance(b1, b2 []byte) (int, error) {
	if len(b1) != len(b2) {
		return 0, errors.New("HammingDistance: buffers must have equal length")
	}
	var res int
	for i := 0; i < len(b1); i++ {
		res += bits.OnesCount8(b1[i] ^ b2[i])
	}
	return res, nil
}

// MakeBlocks takes a buffer and returns chunks of length blockSize.
func MakeBlocks(blockSize int, buf []byte) ([][]byte, error) {
	n := len(buf) / blockSize
	if n == 0 {
		return nil, errors.New("MakeBlocks: buffer length must be greater than block size")
	}
	res := make([][]byte, n)
	for i := 0; i < n; i++ {
		res[i] = make([]byte, blockSize)
		if m := copy(res[i], buf[i*blockSize:]); m != blockSize {
			panic("MakeBlocks: insufficient data copied")
		}
	}
	return res, nil
}

// AverageHammingDistance returns the average edit distance between consecutive blocks.
func AverageHammingDistance(blocks [][]byte) (float64, error) {
	n := len(blocks) - 1
	if n <= 0 {
		return 0.0, errors.New("AverageHammingDistance: need more than 1 block")
	}
	var res float64
	for i := 0; i < n; i++ {
		m, err := HammingDistance(blocks[i], blocks[i+1])
		if err != nil {
			return 0.0, err
		}
		res += float64(m) / float64(n)
	}
	return res, nil
}

// breakBlockSize takes an encrypted buffer and returns blocks of the most likely size.
func breakBlockSize(buf []byte) ([][]byte, error) {
	// Guess lower and upper bounds for the key size.
	const lower = 2
	const upper = 64

	best := math.NaN()
	var res [][]byte
	for blockSize := lower; blockSize <= upper; blockSize++ {
		// If the block size is too large, stop and use what we have so far.
		blocks, err := MakeBlocks(blockSize, buf)
		if err != nil {
			break
		}
		distance, err := AverageHammingDistance(blocks)
		if err != nil {
			break
		}
		if math.IsNaN(best) || distance < best {
			best = distance
			res = blocks
		}
	}
	if math.IsNaN(best) {
		return nil, errors.New("breakBlockSize: nothing found")
	}
	return res, nil
}

// TransposeBlocks makes a block out of the first byte of every block,
// another block out of the second byte of every block, and so on.
func TransposeBlocks(blocks [][]byte) [][]byte {
	// Errors should have been caught already, so panic.
	if len(blocks) <= 1 {
		panic("TransposeBlocks: need more than 1 block")
	}
	blockSize := len(blocks[0])
	if blockSize == 0 {
		panic("TransposeBlocks: block size must be nonzero")
	}
	for _, buf := range blocks {
		if len(buf) != blockSize {
			panic("TransposeBlocks: blocks must have equal length")
		}
	}
	res := make([][]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		res[i] = make([]byte, len(blocks))
		for j := 0; j < len(blocks); j++ {
			res[i][j] = blocks[j][i]
		}
	}
	return res
}

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

// breakTransposedBlock returns the most likely single-byte key for a transposed block.
func breakTransposedBlock(buf []byte, scoreFunc func([]byte) float64) byte {
	var best float64
	var res byte
	for i, try := range allXORByteBuffers(buf) {
		if score := scoreFunc(try); score > best {
			best = score
			res = byte(i)
		}
	}
	return res
}

// breakRepeatingXOR takes an encrypted buffer and returns the key.
func breakRepeatingXOR(buf []byte, scoreFunc func([]byte) float64) ([]byte, error) {
	blocks, err := breakBlockSize(buf)
	if err != nil {
		return nil, err
	}
	keyBlocks := TransposeBlocks(blocks)
	key := make([]byte, len(keyBlocks))
	for i := 0; i < len(keyBlocks); i++ {
		key[i] = breakTransposedBlock(keyBlocks[i], scoreFunc)
	}
	return key, nil
}

// min returns the smaller of two integers.
func min(n, m int) int {
	if n < m {
		return n
	}
	return m
}

// XORBytes produces the XOR combination of two buffers.
func XORBytes(dst, b1, b2 []byte) int {
	n := min(len(b1), len(b2))
	for i := 0; i < n; i++ {
		dst[i] = b1[i] ^ b2[i]
	}
	return n
}

// XORCipher is a repeating XOR cipher.
type XORCipher struct {
	key []byte
}

// NewCipher creates a new XOR cipher.
func NewCipher(key []byte) *XORCipher {
	return &XORCipher{key}
}

// Crypt encrypts or decrypts a buffer.
func (x *XORCipher) Crypt(dst, src []byte) {
	for {
		n := XORBytes(dst, src, x.key)
		if n == 0 {
			break
		}
		src = src[n:]
		dst = dst[n:]
	}
}

// ReadBase64 reads base64-encoded data and returns a decoded buffer.
func ReadBase64(in io.Reader) ([]byte, error) {
	dec := base64.NewDecoder(base64.StdEncoding, in)
	buf, err := ioutil.ReadAll(dec)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// readAndDecryptBase64 reads base64-encoded data encrypted with a
// repeating XOR cipher, breaks the cipher, and prints the plaintext.
func readAndDecryptBase64(in io.Reader, scoreFunc func([]byte) float64) {
	var buf, key []byte
	var err error
	buf, err = ReadBase64(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	key, err = breakRepeatingXOR(buf, scoreFunc)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	// Generate a new cipher from the key.
	x := NewCipher(key)

	// Decrypt the data in place.
	x.Crypt(buf, buf)
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
		readAndDecryptBase64(os.Stdin, scoreFunc)
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		readAndDecryptBase64(f, scoreFunc)
		f.Close()
	}
}
