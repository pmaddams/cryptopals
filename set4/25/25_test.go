package main

import (
	"bytes"
	weak "math/rand"
	"testing"
	"time"
)

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
				t.Errorf("RandomBytes created identical buffers %v and %v",
					cases[i], cases[j])
			}
		}
	}
}
