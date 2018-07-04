package main

import (
	"bytes"
	weak "math/rand"
	"reflect"
	"testing"
	"time"
)

func TestRandomBytes(t *testing.T) {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	n := weak.Intn(1024)

	var cases [][]byte
	for i := 0; i < 5; i++ {
		buf := RandomBytes(n)
		if len(buf) != n {
			t.Errorf("RandomBytes(%v) == %v, length %v",
				n, buf, len(buf))
		}
		cases = append(cases, buf)
		for j := 0; j < i; j++ {
			if bytes.Equal(cases[i], cases[j]) {
				t.Errorf("identical buffers %v and %v", cases[i], cases[j])
			}
		}
	}
}

func TestPKCS7Pad(t *testing.T) {
	cases := []struct {
		buf       []byte
		blockSize int
		want      []byte
	}{
		{
			[]byte{0},
			3,
			[]byte{0, 2, 2},
		},
		{
			[]byte{0, 0},
			3,
			[]byte{0, 0, 1},
		},
		{
			[]byte{0, 0, 0},
			3,
			[]byte{0, 0, 0, 3, 3, 3},
		},
	}
	for _, c := range cases {
		got := PKCS7Pad(c.buf, c.blockSize)
		if !bytes.Equal(got, c.want) {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestPKCS7Unpad(t *testing.T) {
	cases := []struct {
		buf       []byte
		blockSize int
		want      []byte
	}{
		{
			[]byte{0, 2, 2},
			3,
			[]byte{0},
		},
		{
			[]byte{0, 0, 1},
			3,
			[]byte{0, 0},
		},
		{
			[]byte{0, 0, 0, 3, 3, 3},
			3,
			[]byte{0, 0, 0},
		},
	}
	for _, c := range cases {
		got, _ := PKCS7Unpad(c.buf, c.blockSize)
		if !bytes.Equal(got, c.want) {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

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
