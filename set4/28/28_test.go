package main

import (
	"bytes"
	weak "math/rand"
	"testing"
	"time"
)

func TestRandomBytes(t *testing.T) {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	length := weak.Intn(1024)

	var cases [][]byte
	for i := 0; i < 5; i++ {
		buf := RandomBytes(length)
		if len(buf) != length {
			t.Errorf("RandomBytes(%v) == %v, length %v",
				length, buf, len(buf))
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
