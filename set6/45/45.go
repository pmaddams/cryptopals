package main

import (
	"crypto/dsa"
	"errors"
	"math/big"
	"strings"
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
	params := dsa.Parameters{
		P: p,
		Q: q,
		G: new(big.Int).Add(p, one),
	}
}
