package main

import (
	"crypto/rsa"
	"math/big"
)

func rsaPaddingOracle(priv *rsa.PrivateKey) func([]byte) error {
	return func(ciphertext []byte) error {
		_, err := rsa.DecryptPKCS1v15(nil, priv, ciphertext)
		return err
	}
}

type interval struct {
	lo *big.Int
	hi *big.Int
}

type rsaBreaker struct {
	rsa.PublicKey
	oracle func([]byte) error
	b      *big.Int
	c      *big.Int
	s      *big.Int
	m      []interval
}

func newRSABreaker(pub *rsa.PublicKey, oracle func([]byte) error) *rsaBreaker {
	return nil
}

func main() {
}
