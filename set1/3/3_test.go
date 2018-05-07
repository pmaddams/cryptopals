package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestLetterFrequency(t *testing.T) {
	cases := []struct {
		s    string
		want map[byte]float64
	}{
		{
			"hello world",
			map[byte]float64{
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
		got, _ := LetterFrequency(strings.NewReader(c.s))
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("LetterFrequency(%v) == %v, want %v",
				c.s, got, c.want)
		}
	}
}

func TestScore(t *testing.T) {
	m, _ := LetterFrequency(strings.NewReader("hello world"))
	cases := []struct {
		s    string
		want float64
	}{
		{
			"",
			0.0,
		},
		{
			" ",
			1.0 / 11.0,
		},
		{
			"hell",
			1.0/11.0 + 1.0/11.0 + 3.0/11.0 + 3.0/11.0,
		},
	}
	for _, c := range cases {
		got := Score(m, []byte(c.s))
		if got != c.want {
			t.Errorf("Score(%v) == %v, want %v",
				c.s, got, c.want)
		}
	}
}
