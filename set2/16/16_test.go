package main

import (
	"bytes"
	"encoding/hex"
	weak "math/rand"
	"testing"
	"time"
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
			t.Errorf("got %v, want %v", got, c.want)
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
			t.Errorf("got length %v, want length %v", len(buf), n)
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

func TestXORBytes(t *testing.T) {
	decodeString := func(s string) []byte {
		buf, _ := hex.DecodeString(s)
		return buf
	}
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
		XORBytes(dst, c.b1, c.b2)
		if !bytes.Equal(dst, c.want) {
			t.Errorf("got %v, want %v", dst, c.want)
		}
	}
}
