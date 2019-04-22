package main

import (
	"bytes"
	"crypto/cipher"
	"reflect"
	"strings"
	"testing"
)

func TestAverageDistance(t *testing.T) {
	cases := []struct {
		buf       []byte
		blockSize int
		want      float64
	}{
		{
			[]byte{0, 1, 2, 3},
			2,
			float64(1+1) / float64(1) / float64(2),
		},
		{
			[]byte{0, 1, 2, 3, 4, 5},
			2,
			float64(1+1+2+2) / float64(2) / float64(2),
		},
		{
			[]byte{0, 1, 2, 3, 4, 5},
			3,
			float64(2+2+3) / float64(1) / float64(3),
		},
	}
	for _, c := range cases {
		if got, _ := AverageDistance(c.buf, c.blockSize); got != c.want {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestHammingDistance(t *testing.T) {
	cases := []struct {
		b1, b2 []byte
		want   int
	}{
		{
			[]byte("this is a test"),
			[]byte("wokka wokka!!!"),
			37,
		},
		{
			[]byte{0, 0, 0, 0},
			[]byte{1, 2, 4, 8},
			1 + 1 + 1 + 1,
		},
		{
			[]byte{1, 2, 3, 4, 5},
			[]byte{6, 7, 8, 9},
			3 + 2 + 3 + 3 + 8,
		},
	}
	for _, c := range cases {
		if got := HammingDistance(c.b1, c.b2); got != c.want {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestTranspose(t *testing.T) {
	cases := []struct {
		blocks [][]byte
		want   [][]byte
	}{
		{
			[][]byte{
				{0, 1},
				{2, 3},
			},
			[][]byte{
				{0, 2},
				{1, 3},
			},
		},
		{
			[][]byte{
				{0, 1},
				{2, 3},
				{4, 5},
			},
			[][]byte{
				{0, 2, 4},
				{1, 3, 5},
			},
		},
		{
			[][]byte{
				{0, 1, 2},
				{3, 4, 5},
			},
			[][]byte{
				{0, 3},
				{1, 4},
				{2, 5},
			},
		},
	}
	for _, c := range cases {
		got, _ := Transpose(c.blocks)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestSubdivide(t *testing.T) {
	cases := []struct {
		buf  []byte
		n    int
		want [][]byte
	}{
		{
			[]byte{1, 2},
			3,
			nil,
		},
		{
			[]byte{1, 2, 3, 4, 5, 6},
			3,
			[][]byte{
				{1, 2, 3},
				{4, 5, 6},
			},
		},
		{
			[]byte{1, 2, 3, 4, 5, 6},
			2,
			[][]byte{
				{1, 2},
				{3, 4},
				{5, 6},
			},
		},
	}
	for _, c := range cases {
		got := Subdivide(c.buf, c.n)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestScoreFunc(t *testing.T) {
	cases := []struct {
		sample string
		s      string
		want   int
	}{
		{
			"hola",
			"hello world",
			6,
		},
		{
			"世界再见",
			"你好世界",
			2,
		},
	}
	for _, c := range cases {
		score, err := ScoreFunc(strings.NewReader(c.sample))
		if err != nil {
			t.Fatal(err)
		}
		if got := score([]byte(c.s)); got != c.want {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestSymbolCounts(t *testing.T) {
	cases := []struct {
		s    string
		want map[rune]int
	}{
		{
			"hello world",
			map[rune]int{
				'h': 1,
				'e': 1,
				'l': 3,
				'o': 2,
				' ': 1,
				'w': 1,
				'r': 1,
				'd': 1,
			},
		},
		{
			"你好世界",
			map[rune]int{
				'你': 1,
				'好': 1,
				'世': 1,
				'界': 1,
			},
		},
	}
	for _, c := range cases {
		got, _ := SymbolCounts(strings.NewReader(c.s))
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestXORSingleByte(t *testing.T) {
	cases := []struct {
		src  []byte
		b    byte
		want []byte
	}{
		{
			[]byte{0, 1, 2, 3, 4, 5},
			1,
			[]byte{1, 0, 3, 2, 5, 4},
		},
		{
			[]byte{0, 1, 2, 3, 4, 5},
			2,
			[]byte{2, 3, 0, 1, 6, 7},
		},
		{
			[]byte{0, 1, 2, 3, 4, 5},
			3,
			[]byte{3, 2, 1, 0, 7, 6},
		},
	}
	dst := make([]byte, 6)
	for _, c := range cases {
		XORSingleByte(dst, c.src, c.b)
		if !bytes.Equal(dst, c.want) {
			t.Errorf("got %v, want %v", dst, c.want)
		}
	}
}

func TestXORCipher(t *testing.T) {
	cases := []struct {
		stream    cipher.Stream
		src, want []byte
	}{
		{
			NewXORCipher([]byte{1, 2}),
			[]byte{1, 2, 3, 4, 5, 6},
			[]byte{0, 0, 2, 6, 4, 4},
		},
		{
			NewXORCipher([]byte{1, 2, 3}),
			[]byte{1, 2, 3, 4, 5, 6},
			[]byte{0, 0, 0, 5, 7, 5},
		},
		{
			NewXORCipher([]byte{1, 2, 3, 4}),
			[]byte{1, 2, 3, 4, 5, 6},
			[]byte{0, 0, 0, 0, 4, 4},
		},
	}
	for _, c := range cases {
		dst := make([]byte, len(c.src))
		c.stream.XORKeyStream(dst, c.src)
		if !bytes.Equal(dst, c.want) {
			t.Errorf("got %v, want %v", dst, c.want)
		}
	}
}
