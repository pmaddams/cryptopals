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
