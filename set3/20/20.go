package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sort"
)

// AES always has a block size of 128 bits (16 bytes).
const aesBlockSize = 16

// sample is a file with symbol frequencies similar to the expected plaintext.
const sample = "alice.txt"

// scoreBytes must be generated at runtime from the sample file.
var scoreBytes func([]byte) float64

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
	for i := 0; i < len(src); i++ {
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

// Lengths returns a slice of integer buffer lengths.
func Lengths(bufs [][]byte) []int {
	var res []int
	for _, buf := range bufs {
		res = append(res, len(buf))
	}
	return res
}

// Median returns the median value of a slice of integers.
func Median(nums []int) (int, error) {
	if len(nums) == 0 {
		return 0, errors.New("Median: no data")
	}
	sort.Ints(nums)
	return nums[len(nums)/2], nil
}

// Truncate returns a slice of buffers truncated to n bytes long.
func Truncate(bufs [][]byte, n int) [][]byte {
	var res [][]byte
	for _, buf := range bufs {
		// Discard buffers fewer than n bytes long.
		if len(buf) >= n {
			res = append(res, buf[:n])
		}
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
	for i := 1; i < len(nums); i++ {
		if nums[i] != nums[0] {
			return nil, errors.New("Transpose: buffers must have equal length")
		}
	}
	res := make([][]byte, nums[0])
	for i := 0; i < len(res); i++ {
		res[i] = make([]byte, len(bufs))
		for j := 0; j < len(res[i]); j++ {
			res[i][j] = bufs[j][i]
		}
	}
	return res, nil
}

// breakIdenticalCTR returns the keystream used to encrypt buffers with identical CTR.
func breakIdenticalCTR(bufs [][]byte) ([]byte, error) {
	n, err := Median(Lengths(bufs))
	if err != nil {
		return nil, err
	}
	blocks, err := Transpose(Truncate(bufs, n))
	if err != nil {
		return nil, err
	}
	keystream := make([]byte, n)
	for i, block := range blocks {
		keystream[i] = breakSingleXOR(block)
	}
	return keystream, nil
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(length int) []byte {
	res := make([]byte, length)
	if _, err := rand.Read(res); err != nil {
		panic(fmt.Sprintf("RandomBytes: %s", err.Error()))
	}
	return res
}

// decodeAndEncrypt reads lines of base64-encoded text and encrypts them with an identical CTR keystream.
func decodeAndEncrypt(in io.Reader, block cipher.Block, iv []byte) ([][]byte, error) {
	input := bufio.NewScanner(in)
	var res [][]byte
	for input.Scan() {
		line, err := base64.StdEncoding.DecodeString(input.Text())
		if err != nil {
			return nil, err
		}
		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(line, line)
		res = append(res, line)
	}
	if err := input.Err(); err != nil {
		return nil, err
	}
	return res, nil
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

// decryptAndPrint decrypts and prints buffers encrypted with an identical CTR keystream.
func decryptAndPrint(bufs [][]byte) {
	keystream, err := breakIdenticalCTR(bufs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	for _, buf := range bufs {
		n := XORBytes(buf, buf, keystream)
		fmt.Println(string(buf[:n]))
	}
}

func init() {
	// Generate scoreBytes from the sample file.
	f, err := os.Open(sample)
	defer f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	m, err := SymbolFrequencies(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	scoreBytes = func(buf []byte) float64 {
		return ScoreBytesWithMap(buf, m)
	}
}

func main() {
	block, err := aes.NewCipher(RandomBytes(aesBlockSize))
	if err != nil {
		panic(err.Error())
	}
	iv := RandomBytes(block.BlockSize())

	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		lines, err := decodeAndEncrypt(os.Stdin, block, iv)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return
		}
		decryptAndPrint(lines)
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		lines, err := decodeAndEncrypt(f, block, iv)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		decryptAndPrint(lines)
		f.Close()
	}
}
