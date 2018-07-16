package main

import (
	"bufio"
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	weak "math/rand"
	"os"
	"strings"
	"time"
)

const (
	dsaDefaultP = `800000000000000089e1855218a0e7dac38136ffafa72eda7
859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
1a584471bb1`
	dsaDefaultQ = `f4f47f05794b256174bba6e9b396a7707e563c5b`
)

var one = big.NewInt(1)

// equal returns true if two arbitrary-precision integers are equal.
func equal(z1, z2 *big.Int) bool {
	return z1.Cmp(z2) == 0
}

// magicSignature returns a DSA signature that will verify anything.
func magicSignature(pub *dsa.PublicKey) (*big.Int, *big.Int, error) {
	if !equal(pub.G, new(big.Int).Add(pub.P, one)) {
		return nil, nil, errors.New("magicSignature: invalid generator")
	}
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	z, err := rand.Int(weak, pub.Q)
	if err != nil {
		panic(err)
	}
	r := new(big.Int).Exp(pub.Y, z, pub.P)
	r.Mod(r, pub.Q)

	s := new(big.Int).ModInverse(z, pub.Q)
	s.Mul(s, r)
	s.Mod(s, pub.Q)

	return r, s, nil
}

// verifyAnything reads lines of input and verifies them with a fake signature.
func verifyAnything(in io.Reader, pub *dsa.PublicKey) error {
	r, s, err := magicSignature(pub)
	if err != nil {
		return err
	}
	input := bufio.NewScanner(in)
	h := sha256.New()
	for input.Scan() {
		h.Reset()
		h.Write(input.Bytes())
		sum := h.Sum([]byte{})
		if !dsa.Verify(pub, sum, r, s) {
			return errors.New("verifyAnything: verification failed")
		}
		fmt.Printf("verified %q\n", input.Text())
	}
	return input.Err()
}

// ParseBigInt converts a string to an arbitrary-precision integer.
func ParseBigInt(s string, base int) (*big.Int, error) {
	if base < 0 || base > 16 {
		return nil, errors.New("ParseBigInt: invalid base")
	}
	s = strings.Replace(s, "\n", "", -1)
	z, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, errors.New("ParseBigInt: invalid string")
	}
	return z, nil
}

func main() {
	p, err := ParseBigInt(dsaDefaultP, 16)
	if err != nil {
		panic(err)
	}
	q, err := ParseBigInt(dsaDefaultQ, 16)
	if err != nil {
		panic(err)
	}
	y, err := ParseBigInt(`2d026f4bf30195ede3a088da85e398ef869611d0f68f07
13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
2971c3de5084cce04a2e147821`, 16)
	if err != nil {
		panic(err)
	}
	pub := &dsa.PublicKey{
		Parameters: dsa.Parameters{
			P: p,
			Q: q,
			G: new(big.Int).Add(p, one),
		},
		Y: y,
	}
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := verifyAnything(os.Stdin, pub); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := verifyAnything(f, pub); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
