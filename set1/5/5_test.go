package main

import (
	"bytes"
	"encoding/hex"
	weak "math/rand"
	"testing"
	"time"
)

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

// randRange generates a pseudo-random integer in [lo, hi).
func randRange(rng *weak.Rand, lo int, hi int) int {
	if lo < 0 || lo >= hi {
		panic("randRange: invalid range")
	}
	return rng.Intn(hi-lo) + lo
}

func TestCrypt(t *testing.T) {
	// Default test case.
	const s = `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

	src := []byte(s)
	dst := make([]byte, len(src))
	want := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" +
		"a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	x := NewCipher([]byte("ICE"))
	x.Crypt(dst, src)

	if hex.EncodeToString(dst) != want {
		t.Error("Crypt: default test case failed")
	}

	// Generate additional pseudo-random test cases using weak RNG.
	rng := weak.New(weak.NewSource(time.Now().UnixNano()))
	for i := 0; i < 10; i++ {
		// Generate a random buffer between 100 and 1000 bytes long.
		n := randRange(rng, 100, 1000)
		src, dst, want := make([]byte, n), make([]byte, n), make([]byte, n)
		rng.Read(src)

		// Generate a random key between 10 and n bytes long.
		m := randRange(rng, 10, n)
		key := make([]byte, m)
		rng.Read(key)

		for i := 0; i < len(want); i += len(key) {
			XORBytes(want[i:], src[i:], key)
		}
		x := NewCipher(key)
		x.Crypt(dst, src)

		if !bytes.Equal(dst, want) {
			t.Errorf("Crypt(%v, %v), want %v", dst, src, want)
		}
	}
}
