package main

import (
	"bytes"
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
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestScoreBytesWithMap(t *testing.T) {
	symbolFrequencies := func(s string) map[rune]float64 {
		m, _ := SymbolFrequencies(strings.NewReader(s))
		return m
	}
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
		got := ScoreBytesWithMap([]byte(c.s), c.m)
		if got != c.want {
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
			t.Errorf("got %v, want %v", got, c.want)
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
			t.Errorf("got %v, want %v", got, c.want)
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
			t.Errorf("got %v, want %v", got, c.want)
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
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestRandomBytes(t *testing.T) {
	var bufs [][]byte
	for i := 0; i < 5; i++ {
		bufs = append(bufs, RandomBytes(16))
		for j := 0; j < i; j++ {
			if bytes.Equal(bufs[i], bufs[j]) {
				t.Errorf("identical buffers %v and %v", bufs[i], bufs[j])
			}
		}
	}
}

func TestXORBytes(t *testing.T) {
	cases := []struct {
		b1, b2, want []byte
	}{
		{
			[]byte{0, 0, 0, 0},
			[]byte{1, 1, 1, 1},
			[]byte{1, 1, 1, 1},
		},
		{
			[]byte{1, 0, 1, 0},
			[]byte{1, 0, 1, 0, 1, 0},
			[]byte{0, 0, 0, 0},
		},
		{
			[]byte{1, 0, 1, 0, 1, 0},
			[]byte{1, 1, 1, 1},
			[]byte{0, 1, 0, 1},
		},
	}
	for _, c := range cases {
		n := XORBytes(c.b1, c.b1, c.b2)
		got := c.b1[:n]
		if !bytes.Equal(got, c.want) {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}
