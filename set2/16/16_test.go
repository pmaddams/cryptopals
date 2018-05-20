package main

import (
	"bytes"
	"crypto/cipher"
	"reflect"
	"testing"
)

func TestUserData(t *testing.T) {
	cases := []struct {
		s, want string
	}{
		{
			"",
			"comment1=cooking%20MCs;userdata=;comment2=%20like%20a%20pound%20of%20bacon",
		},
		{
			";admin=true",
			"comment1=cooking%20MCs;userdata=%3Badmin%3Dtrue;comment2=%20like%20a%20pound%20of%20bacon",
		},
		{
			"\";admin=true\"",
			"comment1=cooking%20MCs;userdata=%22%3Badmin%3Dtrue%22;comment2=%20like%20a%20pound%20of%20bacon",
		},
	}
	for _, c := range cases {
		if got := UserData(c.s); got != c.want {
			t.Errorf("UserData(%v) == %v, want %v",
				c.s, got, c.want)
		}
	}
}

func TestAdminTrue(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{
			"comment1=cooking%20MCs;userdata=%3Badmin%3Dtrue;comment2=%20like%20a%20pound%20of%20bacon",
			false,
		},
		{
			"comment1=cooking%20MCs;userdata=%22%3Badmin%3Dtrue%22;comment2=%20like%20a%20pound%20of%20bacon",
			false,
		},
		{
			"comment1=cooking%20MCs;userdata=;admin=true;comment2=%20like%20a%20pound%20of%20bacon",
			true,
		},
	}
	for _, c := range cases {
		if got := AdminTrue(c.s); got != c.want {
			t.Errorf("AdminTrue(%v) == %v, want %v",
				c.s, got, c.want)
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
