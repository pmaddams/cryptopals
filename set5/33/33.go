package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

const (
	p = `ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff`
	g = `2`
)

// DHParameters contains a modulus and base.
type DHParameters struct {
	P, G *big.Int
}

// DHPublicKey contains parameters and a public key.
type DHPublicKey struct {
	DHParameters
	pub *big.Int
}

// DHPrivateKey contains a public key and private key.
type DHPrivateKey struct {
	DHPublicKey
	priv *big.Int
}

// DHGenerateParams initializes a set of parameters.
func DHGenerateParams(params *DHParameters) error {
	var ok bool
	if params.P, ok = new(big.Int).SetString(strings.Replace(p, "\n", "", -1), 16); !ok {
		return errors.New("DHGenerateParams: invalid parameters")
	}
	if params.G, ok = new(big.Int).SetString(g, 16); !ok {
		return errors.New("DHGenerateParams: invalid parameters")
	}
	return nil
}

// DHGenerateKey initializes a private key.
func DHGenerateKey(priv *DHPrivateKey, r io.Reader) error {
	var err error
	if priv.P == nil || priv.G == nil {
		return errors.New("DHGenerateKey: uninitialized parameters")
	}
	if priv.priv, err = rand.Int(r, priv.P); err != nil {
		return err
	}
	priv.pub = new(big.Int).Exp(priv.G, priv.priv, priv.P)

	return nil
}

func main() {
	var priv DHPrivateKey
	if err := DHGenerateParams(&priv.DHParameters); err != nil {
		panic(err)
	}
	if err := DHGenerateKey(&priv, rand.Reader); err != nil {
		panic(err)
	}
	fmt.Println(priv)
	fmt.Println(priv.priv)
	fmt.Println(priv.pub)
}
