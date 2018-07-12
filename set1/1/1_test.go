package main

import (
	"encoding/base64"
	"encoding/hex"
	weak "math/rand"
	"testing"
	"time"
)

func init() { weak.Seed(time.Now().UnixNano()) }

func TestHexToBase64(t *testing.T) {
	for i := 0; i < 5; i++ {
		n := 16 + weak.Intn(16)
		buf := make([]byte, n)
		weak.Read(buf)

		s := hex.EncodeToString(buf)
		want := base64.StdEncoding.EncodeToString(buf)

		got, err := HexToBase64(s)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}
