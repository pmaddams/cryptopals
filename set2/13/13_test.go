package main

import (
	"bytes"
	"crypto/cipher"
	"reflect"
	"testing"
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
			t.Errorf("ProfileFor(%v) == %v, want %v",
				c.email, got, c.want)
		}
	}
}

func TestIsAdmin(t *testing.T) {
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
		if got := IsAdmin(c.query); got != c.want {
			t.Errorf("IsAdmin(%v) == %v, want %v",
				c.query, got, c.want)
		}
	}
}

func TestRandomCipher(t *testing.T) {
	cases := []cipher.Block{}
	for i := 0; i < 5; i++ {
		cases = append(cases, RandomCipher())
		for j := 0; j < i; j++ {
			if reflect.DeepEqual(cases[i], cases[j]) {
				t.Errorf("RandomCipher created identical ciphers %v and %v",
					cases[i], cases[j])
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
			t.Errorf("PKCS7Pad(%v, %v) == %v, want %v",
				c.buf, c.blockSize, got, c.want)
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
			t.Errorf("PKCS7Unpad(%v, %v) == %v, want %v",
				c.buf, c.blockSize, got, c.want)
		}
	}
}
