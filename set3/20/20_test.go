package main

import (
	"bytes"
	"crypto/cipher"
	"reflect"
	"strings"
	"testing"
)

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

func TestScore(t *testing.T) {
	cases := []struct {
		m    map[rune]float64
		s    string
		want float64
	}{
		{
			symbolFrequencies("hello world"),
			"hola",
			1.0/11.0 + 2.0/11.0 + 3.0/11.0,
		},
		{
			symbolFrequencies("你好世界"),
			"世界再见",
			1.0/4.0 + 1.0/4.0,
		},
	}
	for _, c := range cases {
		got := Score(c.m, []byte(c.s))
		if got != c.want {
			t.Errorf("Score(%v) == %v, want %v",
				c.s, got, c.want)
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
