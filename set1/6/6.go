package main

import (
	"errors"
	"math/bits"
)

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
			return nil, errors.New("MakeBlocks: insufficient data copied")
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

func main() {
}
