package main

import (
	"bytes"
	"testing"
)

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

func TestMinimum(t *testing.T) {
	cases := []struct {
		nums []int
		want int
	}{
		{
			[]int{0},
			0,
		},
		{
			[]int{2, 1},
			1,
		},
		{
			[]int{-1, 2, 3},
			-1,
		},
	}
	for _, c := range cases {
		got := Minimum(c.nums[0], c.nums[1:]...)
		if got != c.want {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}
