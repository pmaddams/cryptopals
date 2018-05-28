package main

import (
	"bytes"
	"crypto/cipher"
	"reflect"
	"strings"
	"testing"
)

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
			[]byte{1, 2, 3, 4},
			[]byte{2, 3, 4, 5},
			2 + 1 + 3 + 1,
		},
	}
	for _, c := range cases {
		got := HammingDistance(c.b1, c.b2)
		if got != c.want {
			t.Errorf("HammingDistance(%v, %v) == %v, want %v",
				c.b1, c.b2, got, c.want)
		}
	}
}

func TestNormalizedDistance(t *testing.T) {
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
		if got, _ := NormalizedDistance(c.buf, c.blockSize); got != c.want {
			t.Errorf("NormalizedDistance(%v, %v) == %v, want %v",
				c.buf, c.blockSize, got, c.want)
		}
	}
}

func TestSymbolFrequencies(t *testing.T) {
	cases := []struct {
		s    string
		want map[rune]float64
	}{
		{
			"hello world",
			map[rune]float64{
				'h': 1.0 / 11.0,
				'e': 1.0 / 11.0,
				'l': 3.0 / 11.0,
				'o': 2.0 / 11.0,
				' ': 1.0 / 11.0,
				'w': 1.0 / 11.0,
				'r': 1.0 / 11.0,
				'd': 1.0 / 11.0,
			},
		},
		{
			"你好世界",
			map[rune]float64{
				'你': 1.0 / 4.0,
				'好': 1.0 / 4.0,
				'世': 1.0 / 4.0,
				'界': 1.0 / 4.0,
			},
		},
	}
	for _, c := range cases {
		got, _ := SymbolFrequencies(strings.NewReader(c.s))
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("SymbolFrequencies(%v) == %v, want %v",
				c.s, got, c.want)
		}
	}
}

func symbolFrequencies(s string) map[rune]float64 {
	m, _ := SymbolFrequencies(strings.NewReader(s))
	return m
}

func TestScoreBufWithMap(t *testing.T) {
	cases := []struct {
		s    string
		m    map[rune]float64
		want float64
	}{
		{
			"hola",
			symbolFrequencies("hello world"),
			1.0/11.0 + 2.0/11.0 + 3.0/11.0,
		},
		{
			"世界再见",
			symbolFrequencies("你好世界"),
			1.0/4.0 + 1.0/4.0,
		},
	}
	for _, c := range cases {
		got := ScoreBufWithMap([]byte(c.s), c.m)
		if got != c.want {
			t.Errorf("ScoreBufWithMap(%v, %v) == %v, want %v",
				c.s, c.m, got, c.want)
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
			t.Errorf("XORSingleByte(%v, %v, %v), want %v",
				dst, c.src, c.b, c.want)
		}
	}
}

func TestLengths(t *testing.T) {
	cases := []struct {
		bufs [][]byte
		want []int
	}{
		{
			[][]byte{},
			nil,
		},
		{
			[][]byte{
				{},
			},
			[]int{0},
		},
		{
			[][]byte{
				{1},
				{1, 2},
				{1, 2, 3},
			},
			[]int{1, 2, 3},
		},
	}
	for _, c := range cases {
		got := Lengths(c.bufs)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Lengths(%v) == %v, want %v",
				c.bufs, got, c.want)
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
			t.Errorf("Subdivide(%v, %v) == %v, want %v",
				c.buf, c.n, got, c.want)
		}
	}
}

func TestTranspose(t *testing.T) {
	cases := []struct {
		bufs [][]byte
		want [][]byte
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
		got, _ := Transpose(c.bufs)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Transpose(%v) == %v, want %v",
				c.bufs, got, c.want)
		}
	}
}

func TestXORKeyStream(t *testing.T) {
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
		if c.stream.XORKeyStream(dst, c.src); !bytes.Equal(dst, c.want) {
			t.Errorf("(%v).XORKeyStream(%v, %v), want %v",
				c.stream, dst, c.src, c.want)
		}
	}
}
