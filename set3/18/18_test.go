package main

import (
	"reflect"
	"testing"
)

func TestBytesToUint64(t *testing.T) {
	cases := []struct {
		buf  []byte
		want []uint64
	}{
		{
			[]byte{1, 0, 0, 0, 0, 0, 0, 0},
			[]uint64{1},
		},
		{
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},
			[]uint64{0, 1},
		},
		{
			[]byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},
			[]uint64{256, 256},
		},
	}
	for _, c := range cases {
		got := BytesToUint64(c.buf)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("BytesToUint64(%v) == %v, want %v",
				c.buf, got, c.want)
		}
	}
}

func TestUint64ToBytes(t *testing.T) {
	cases := []struct {
		nums []uint64
		want []byte
	}{
		{
			[]uint64{1},
			[]byte{1, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			[]uint64{0, 1},
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			[]uint64{256, 256},
			[]byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},
		},
	}
	for _, c := range cases {
		got := Uint64ToBytes(c.nums)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Uint64ToBytes(%v) == %v, want %v",
				c.nums, got, c.want)
		}
	}
}
