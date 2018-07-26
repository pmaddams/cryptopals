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

// sample is a file similar to the expected plaintext.
const sample = "alice.txt"

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
func scoreFunc(name string) (func([]byte) int, error) {
	f, err := os.Open(name)
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
		best int
		key  byte
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

// breakCTR returns the keystream used to encrypt buffers with identical CTR.
func breakCTR(bufs [][]byte, score func([]byte) int) ([]byte, error) {
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
			keystream[i] = breakSingleXOR(blocks[i], score)
			wg.Done()
		}(i)
	}
	wg.Wait()
	return keystream, nil
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

// encryptCTR reads lines of base64-encoded text and encrypts them with an identical CTR keystream.
func encryptCTR(in io.Reader, c cipher.Block, iv []byte) ([][]byte, error) {
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

// decryptCTR decrypts and prints buffers encrypted with an identical CTR keystream.
func decryptCTR(bufs [][]byte, score func([]byte) int) error {
	keystream, err := breakCTR(bufs, score)
	if err != nil {
		return err
	}
	for _, buf := range bufs {
		n := XORBytes(buf, buf, keystream)
		fmt.Println(string(buf[:n]))
	}
	return nil
}

func main() {
	score, err := scoreFunc(sample)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	c, err := aes.NewCipher(RandomBytes(aes.BlockSize))
	if err != nil {
		panic(err)
	}
	iv := RandomBytes(c.BlockSize())

	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		lines, err := encryptCTR(os.Stdin, c, iv)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if err := decryptCTR(lines, score); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		lines, err := encryptCTR(f, c, iv)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := decryptCTR(lines, score); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
