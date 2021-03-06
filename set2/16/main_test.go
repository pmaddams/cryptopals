package main

import (
	"bytes"
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
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestIsAdmin(t *testing.T) {
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
		if got := IsAdmin(c.s); got != c.want {
			t.Errorf("got %v, want %v", got, c.want)
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

func TestXORBytes(t *testing.T) {
	cases := []struct {
		b1, b2, want []byte
	}{
		{
			[]byte{0, 0, 0, 0},
			[]byte{1, 1, 1, 1},
			[]byte{1, 1, 1, 1},
		},
		{
			[]byte{1, 0, 1, 0},
			[]byte{1, 0, 1, 0, 1, 0},
			[]byte{0, 0, 0, 0},
		},
		{
			[]byte{1, 0, 1, 0, 1, 0},
			[]byte{1, 1, 1, 1},
			[]byte{0, 1, 0, 1},
		},
	}
	for _, c := range cases {
		n := XORBytes(c.b1, c.b1, c.b2)
		got := c.b1[:n]
		if !bytes.Equal(got, c.want) {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}

func TestMinimum(t *testing.T) {
	cases := []struct {
		nums []int
		want int
	}{
		{
			[]int{0},
			0,
		},
		{
			[]int{2, 1},
			1,
		},
		{
			[]int{-1, 2, 3},
			-1,
		},
	}
	for _, c := range cases {
		got := Minimum(c.nums[0], c.nums[1:]...)
		if got != c.want {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
}
