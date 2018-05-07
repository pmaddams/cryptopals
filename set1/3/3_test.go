package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestSymbols(t *testing.T) {
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
	}
	for _, c := range cases {
		got, _ := Symbols(strings.NewReader(c.s))
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Symbols(%v) == %v, want %v",
				c.s, got, c.want)
		}
	}
}

func symbols(s string) (res map[rune]float64) {
	res, _ = Symbols(strings.NewReader(s))
	return
}

func TestScore(t *testing.T) {
	cases := []struct {
		m    map[rune]float64
		s    string
		want float64
	}{
		{
			symbols("hello world"),
			"hola",
			1.0/11.0 + 2.0/11.0 + 3.0/11.0,
		},
		{
			symbols("你好世界"),
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

func TestXORByte(t *testing.T) {
	cases := []struct {
		got, bytes []byte
		b          byte
		want       []byte
	}{
		{
			make([]byte, 11),
			[]byte("hello world"),
			0,
			[]byte("hello world"),
		},
		{
			make([]byte, 4),
			[]byte{0, 0, 0, 0},
			1,
			[]byte{1, 1, 1, 1},
		},
	}
	for _, c := range cases {
		XORByte(c.got, c.bytes, c.b)
		if !bytes.Equal(c.got, c.want) {
			t.Errorf("XORByte(%v, %v, %v), want %v",
				c.got, c.bytes, c.b, c.want)
		}
	}
}
