package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
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

// Blocks contains buffers guaranteed to be of equal length.
type Blocks struct {
	data [][]byte
}

// NewBlocks generates at least 2 blocks of the given size from a buffer.
func NewBlocks(buf []byte, blockSize int) (*Blocks, error) {
	if blockSize <= 0 {
		return nil, errors.New("NewBlocks: block size must be at least 1")
	}
	count := len(buf) / blockSize
	if count < 2 {
		return nil, errors.New("NewBlocks: must create at least 2 blocks")
	}
	data := make([][]byte, count)
	for i := 0; i < count; i++ {
		data[i] = make([]byte, blockSize)
		copy(data[i], buf[i*blockSize:])
	}
	return &Blocks{data}, nil
}

// blockSize returns the block size.
func (b *Blocks) blockSize() int {
	return len(b.data[0])
}

// count returns the number of blocks.
func (b *Blocks) count() int {
	return len(b.data)
}

// NormalizedDistance returns the normalized edit distance between consecutive blocks.
func (b *Blocks) NormalizedDistance() float64 {
	var res float64
	if b.count() < 2 {
		panic("NormalizedDistance: must have at least 2 blocks")
	}
	numPairs := b.count() - 1
	for i := 0; i < numPairs; i++ {
		// No need to check for an error, since blocks have equal length.
		distance, _ := HammingDistance(b.data[i], b.data[i+1])
		res += float64(distance) / float64(numPairs) / float64(b.blockSize())
	}
	return res
}

// keySizeBlocks takes an encrypted buffer and returns blocks of the probable key size.
func keySizeBlocks(buf []byte) (*Blocks, error) {
	// Guess lower and upper bounds for the key size.
	const lower = 2
	const upper = 64

	// Set best to an impossibly high value.
	best := float64(8 * len(buf))
	var res *Blocks

	for blockSize := lower; blockSize <= upper; blockSize++ {
		// If the block size is too large, stop and use what we have so far.
		b, err := NewBlocks(buf, blockSize)
		if err != nil {
			break
		}
		if distance := b.NormalizedDistance(); distance < best {
			best = distance
			res = b
		}
	}
	if res == nil {
		return nil, errors.New("keySizeBlocks: nothing found")
	}
	return res, nil
}

// Transpose makes a block out of the first byte of every block,
// another block out of the second byte of every block, and so on.
func (b *Blocks) Transpose() *Blocks {
	data := make([][]byte, b.blockSize())
	for i := 0; i < b.blockSize(); i++ {
		data[i] = make([]byte, b.count())
		for j := 0; j < b.count(); j++ {
			data[i][j] = b.data[j][i]
		}
	}
	return &Blocks{data}
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

// breakSingleXOR takes an encrypted buffer and returns the single-byte key.
func breakSingleXOR(buf []byte, scoreFunc func([]byte) float64) byte {
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
	// Each block should have the same size as the key.
	b, err := keySizeBlocks(buf)
	if err != nil {
		return nil, err
	}
	// The number of transposed blocks is equal to the key size,
	// and each block is encrypted with single byte XOR.
	keyBlocks := b.Transpose()
	key := make([]byte, keyBlocks.count())
	for i := 0; i < keyBlocks.count(); i++ {
		key[i] = breakSingleXOR(keyBlocks.data[i], scoreFunc)
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

// readAndDecryptBase64 reads base64-encoded data encrypted with a
// repeating XOR cipher, breaks the cipher, and prints the plaintext.
func readAndDecryptBase64(in io.Reader, scoreFunc func([]byte) float64) {
	var buf, key []byte
	var err error
	buf, err = ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, in))
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
