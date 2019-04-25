// 20. Break fixed-nonce CTR statistically

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

func main() {
	c, err := aes.NewCipher(RandomBytes(aes.BlockSize))
	if err != nil {
		panic(err)
	}
	iv := RandomBytes(c.BlockSize())

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
		lines, err := encrypt(os.Stdin, c, iv)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if err := decrypt(lines, score); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		lines, err := encrypt(f, c, iv)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := decrypt(lines, score); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}

// encrypt reads lines of base64-encoded text and encrypts them with an identical CTR keystream.
func encrypt(in io.Reader, c cipher.Block, iv []byte) ([][]byte, error) {
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

// decrypt decrypts and prints buffers encrypted with an identical CTR keystream.
func decrypt(bufs [][]byte, score func([]byte) int) error {
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

// breakCTR returns the keystream used to encrypt buffers with identical CTR.
func breakCTR(bufs [][]byte, score func([]byte) int) ([]byte, error) {
	size := Median(Lengths(bufs))
	bufs, err := Transpose(Truncate(bufs, size))
	if err != nil {
		return nil, err
	}
	keystream := make([]byte, size)

	var wg sync.WaitGroup
	wg.Add(size)
	for i := 0; i < size; i++ {
		// Capture the value of the loop variable.
		go func(i int) {
			keystream[i] = breakSingleXOR(bufs[i], score)
			wg.Done()
		}(i)
	}
	wg.Wait()

	return keystream, nil
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

// Truncate returns a slice of buffers truncated to n bytes.
func Truncate(bufs [][]byte, n int) [][]byte {
	var res [][]byte
	for _, buf := range bufs {
		// Discard buffers shorter than n bytes.
		if len(buf) >= n {
			res = append(res, buf[:n])
		}
	}
	return res
}

// Median returns the median value of a slice of integers.
func Median(nums []int) int {
	sort.Ints(nums)
	return nums[len(nums)/2]
}

// Lengths returns a slice of buffer lengths.
func Lengths(bufs [][]byte) []int {
	nums := make([]int, len(bufs))
	for i := range nums {
		nums[i] = len(bufs[i])
	}
	return nums
}

// XORBytes produces the XOR combination of two buffers.
func XORBytes(dst, b1, b2 []byte) int {
	n := min(len(b1), len(b2))
	for i := 0; i < n; i++ {
		dst[i] = b1[i] ^ b2[i]
	}
	return n
}

// XORSingleByte produces the XOR combination of a buffer with a single byte.
func XORSingleByte(dst, src []byte, b byte) {
	// Panic if dst is smaller than src.
	for i := range src {
		dst[i] = src[i] ^ b
	}
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

// min returns the smaller of two integers.
func min(n, m int) int {
	if n < m {
		return n
	}
	return m
}
