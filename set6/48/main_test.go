package main

import (
	"bytes"
	weak "math/rand"
	"testing"
	"time"
)

func init() { weak.Seed(time.Now().UnixNano()) }

func TestPKCS1v15CryptPadUnpad(t *testing.T) {
	const size = 256 / 8
	for i := 0; i < 5; i++ {
		want := make([]byte, weak.Intn(size-10))
		weak.Read(want)

		buf, err := PKCS1v15CryptPad(want, size)
		if err != nil {
			t.Fatal(err)
		}
		got, err := PKCS1v15CryptUnpad(buf)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

func TestRandomBytes(t *testing.T) {
	var bufs [][]byte
	for i := 0; i < 5; i++ {
		bufs = append(bufs, RandomBytes(16))
		for j := 0; j < i; j++ {
			if bytes.Equal(bufs[i], bufs[j]) {
				t.Errorf("identical buffers %v and %v", bufs[i], bufs[j])
			}
		}
	}
}

func TestCopyRight(t *testing.T) {
	cases := []struct {
		dst, src, want []byte
	}{
		{
			[]byte{0},
			[]byte{},
			[]byte{0},
		},
		{
			[]byte{0, 1, 2},
			[]byte{3},
			[]byte{0, 1, 3},
		},
		{
			[]byte{1, 2, 3},
			[]byte{4, 5, 6},
			[]byte{4, 5, 6},
		},
	}
	for _, c := range cases {
		CopyRight(c.dst, c.src)
		if !bytes.Equal(c.dst, c.want) {
			t.Errorf("got %v, want %v", c.dst, c.want)
		}
	}
}
