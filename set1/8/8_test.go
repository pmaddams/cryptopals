package main

import "testing"

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
			t.Errorf("IdenticalBlocks(%v, %v) == %v, want %v",
				c.buf, c.blockSize, got, c.want)
		}
	}
}
