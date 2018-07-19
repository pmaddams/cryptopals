package main

import (
	"crypto/rsa"
	"math/big"
)

func validatePKCS1v15(priv *rsa.PrivateKey, ciphertext []byte) error {
	if _, err := rsa.DecryptPKCS1v15(nil, priv, ciphertext); err != nil {
		return err
	}
	return nil
}

func pkcs1v15Oracle(priv *rsa.PrivateKey) func([]byte) error {
	return func(ciphertext []byte) error {
		return validatePKCS1v15(priv, ciphertext)
	}
}

type interval struct {
	lo *big.Int
	hi *big.Int
}

type pkcs1v15OracleBreaker struct {
	rsa.PublicKey
	oracle func([]byte) error
	b      *big.Int
	c      *big.Int
	s      *big.Int
	m      []interval
}

func newPKCS1v15OracleBreaker(pub *rsa.PublicKey, oracle func([]byte) error) *pkcs1v15OracleBreaker {
	return nil
}

func main() {
}
