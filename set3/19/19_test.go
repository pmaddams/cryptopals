package main

import (
	"bytes"
	"encoding/hex"
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

func TestMedian(t *testing.T) {
	cases := []struct {
		nums []int
		want int
	}{
		{
			[]int{1, 2, 3},
			2,
		},
		{
			[]int{1, 3, 3},
			3,
		},
		{
			[]int{1, 1, 1, 1, 2, 2, 3},
			1,
		},
	}
	for _, c := range cases {
		if got, _ := Median(c.nums); got != c.want {
			t.Errorf("Median(%v) == %v, want %v",
				c.nums, got, c.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		bufs [][]byte
		n    int
		want [][]byte
	}{
		{
			[][]byte{
				{1},
				{2, 2},
				{3, 3, 3},
			},
			1,
			[][]byte{
				{1},
				{2},
				{3},
			},
		},
		{
			[][]byte{
				{1},
				{2, 2},
				{3, 3, 3},
			},
			2,
			[][]byte{
				{2, 2},
				{3, 3},
			},
		},
		{
			[][]byte{
				{1},
				{2, 2},
				{3, 3, 3},
			},
			3,
			[][]byte{
				{3, 3, 3},
			},
		},
	}
	for _, c := range cases {
		got := Truncate(c.bufs, c.n)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Truncate(%v, %v) == %v, want %v",
				c.bufs, c.n, got, c.want)
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

func TestRandomBytes(t *testing.T) {
	const length = 10
	cases := [][]byte{}
	for i := 0; i < 5; i++ {
		cases = append(cases, RandomBytes(length))
		for j := 0; j < i; j++ {
			if bytes.Equal(cases[i], cases[j]) {
				t.Errorf("RandomBytes created identical buffers %v and %v",
					cases[i], cases[j])
			}
		}
	}
}

func decodeString(s string) []byte {
	buf, _ := hex.DecodeString(s)
	return buf
}

func TestXORBytes(t *testing.T) {
	cases := []struct {
		b1, b2, want []byte
	}{
		{
			decodeString("1c0111001f010100061a024b53535009181c"),
			decodeString("686974207468652062756c6c277320657965"),
			decodeString("746865206b696420646f6e277420706c6179"),
		},
		{
			[]byte{0, 0, 0, 0},
			[]byte{1, 1, 1, 1},
			[]byte{1, 1, 1, 1},
		},
		{
			[]byte{1, 0, 1, 0},
			[]byte{1, 0, 1, 0},
			[]byte{0, 0, 0, 0},
		},
	}
	for _, c := range cases {
		dst := make([]byte, len(c.b1))
		if XORBytes(dst, c.b1, c.b2); !bytes.Equal(dst, c.want) {
			t.Errorf("XORBytes(%v, %v, %v), want %v",
				dst, c.b1, c.b2, c.want)
		}
	}
}
