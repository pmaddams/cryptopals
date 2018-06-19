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
	"sync"
)

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
	for i := range src {
		dst[i] = src[i] ^ b
	}
}

// breakSingleXOR returns the key used to encrypt a buffer with single byte XOR.
func breakSingleXOR(buf []byte) byte {
	// Don't stomp on the original data.
	tmp := make([]byte, len(buf))
	var (
		best float64
		b    byte
	)
	// Use an integer as the loop variable to avoid overflow.
	for i := 0; i <= 0xff; i++ {
		XORSingleByte(tmp, buf, byte(i))
		if score := scoreBytes(tmp); score > best {
			best = score
			b = byte(i)
		}
	}
	return b
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
	var wg sync.WaitGroup

	for i := range blocks {
		wg.Add(1)
		go func(i int) {
			keystream[i] = breakSingleXOR(blocks[i])
			wg.Done()
		}(i)
	}
	wg.Wait()
	return keystream, nil
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	res := make([]byte, n)
	if _, err := rand.Read(res); err != nil {
		panic(err)
	}
	return res
}

// decodeAndEncrypt reads lines of base64-encoded text and encrypts them with an identical CTR keystream.
func decodeAndEncrypt(in io.Reader, c cipher.Block, iv []byte) ([][]byte, error) {
	input := bufio.NewScanner(in)
	var res [][]byte
	for input.Scan() {
		line, err := base64.StdEncoding.DecodeString(input.Text())
		if err != nil {
			return nil, err
		}
		stream := cipher.NewCTR(c, iv)
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
		fmt.Fprintln(os.Stderr, err)
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
	c, err := aes.NewCipher(RandomBytes(aes.BlockSize))
	if err != nil {
		panic(err)
	}
	iv := RandomBytes(c.BlockSize())

	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		lines, err := decodeAndEncrypt(os.Stdin, c, iv)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		decryptAndPrint(lines)
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		lines, err := decodeAndEncrypt(f, c, iv)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		decryptAndPrint(lines)
		f.Close()
	}
}
