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
			"hello world",
			"hola mundo",
			10,
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
