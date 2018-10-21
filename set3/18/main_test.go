package main

import (
	"reflect"
	"testing"
)

func TestBytesToUint64s(t *testing.T) {
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
			[]uint64{0x100, 0x100},
		},
	}
	for _, c := range cases {
		got := BytesToUint64s(c.buf)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestUint64sToBytes(t *testing.T) {
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
			[]uint64{0x100, 0x100},
			[]byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},
		},
	}
	for _, c := range cases {
		got := Uint64sToBytes(c.nums)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}
