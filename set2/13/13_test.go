package main

import (
	"bytes"
	weak "math/rand"
	"testing"
	"time"
)

func TestProfileFor(t *testing.T) {
	cases := []struct {
		email, want string
	}{
		{
			"foo@bar.com",
			"email=foo%40bar.com&role=user",
		},
		{
			"foo@bar.com&role=admin",
			"email=foo%40bar.com%26role%3Dadmin&role=user",
		},
		{
			"\"&role=admin\"",
			"email=%22%26role%3Dadmin%22&role=user",
		},
	}
	for _, c := range cases {
		if got := ProfileFor(c.email); got != c.want {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestRoleAdmin(t *testing.T) {
	cases := []struct {
		query string
		want  bool
	}{
		{
			"email=foo%40bar.com&role=user",
			false,
		},
		{
			"email=foo%40bar.com%26role%3Dadmin&role=user",
			false,
		},
		{
			"email=foo%40bar.com&role=admin",
			true,
		},
	}
	for _, c := range cases {
		if got := RoleAdmin(c.query); got != c.want {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestRandomBytes(t *testing.T) {
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	n := weak.Intn(1024)

	var bufs [][]byte
	for i := 0; i < 5; i++ {
		buf := RandomBytes(n)
		if len(buf) != n {
			t.Errorf("got length %v, want %v", len(buf), n)
		}
		bufs = append(bufs, buf)
		for j := 0; j < i; j++ {
			if bytes.Equal(bufs[i], bufs[j]) {
				t.Errorf("identical buffers %v and %v", bufs[i], bufs[j])
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
