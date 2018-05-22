package main

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
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

func TestRandomBytes(t *testing.T) {
	const length = 10
	cases := [][]byte{}
	for i := 0; i < 5; i++ {
		cases = append(cases, RandomBytes(length))
		for j := 0; j < i; j++ {
			if bytes.Equal(cases[i], cases[j]) {
				t.Errorf("RandomBytes created identical buffers %v and %v",
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

func decodeString(s string) []byte {
	buf, _ := hex.DecodeString(s)
	return buf
}

func TestXORBytes(t *testing.T) {
	cases := []struct {
		b1, b2, want []byte
	}{
		{
			decodeString("1c0111001f010100061a024b53535009181c"),
			decodeString("686974207468652062756c6c277320657965"),
			decodeString("746865206b696420646f6e277420706c6179"),
		},
		{
			[]byte{0, 0, 0, 0},
			[]byte{1, 1, 1, 1},
			[]byte{1, 1, 1, 1},
		},
		{
			[]byte{1, 0, 1, 0},
			[]byte{1, 0, 1, 0},
			[]byte{0, 0, 0, 0},
		},
	}
	for _, c := range cases {
		dst := make([]byte, len(c.b1))
		if XORBytes(dst, c.b1, c.b2); !bytes.Equal(dst, c.want) {
			t.Errorf("XORBytes(%v, %v, %v), want %v",
				dst, c.b1, c.b2, c.want)
		}
	}
}
