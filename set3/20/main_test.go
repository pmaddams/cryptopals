package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

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
		if got := Median(c.nums); got != c.want {
			t.Errorf("got %v, want %v", got, c.want)
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
			[]int{},
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
