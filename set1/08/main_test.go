package main

import (
	"reflect"
	"testing"
)

func TestBlocks(t *testing.T) {
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
		got := Blocks(c.buf, c.n)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestIdenticalBlocks(t *testing.T) {
	cases := []struct {
		buf       []byte
		blockSize int
		want      bool
	}{
		{
			[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3},
			3,
			true,
		},
		{
			[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 4, 5, 6},
			3,
			true,
		},
		{
			[]byte{1, 2, 3, 1, 3, 2, 3, 1, 3, 2, 3, 1},
			3,
			false,
		},
	}
	for _, c := range cases {
		if got := IdenticalBlocks(c.buf, c.blockSize); got != c.want {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}
