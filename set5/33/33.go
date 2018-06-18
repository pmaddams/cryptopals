package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"strings"
)

const (
	defaultP = `ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff`
	defaultG = `2`
)

// DHPrivateKey contains Diffie-Hellman parameters and a key pair.
type DHPrivateKey struct {
	p, g, pub, priv *big.Int
}

// DHGenerateKey takes a prime modulus and generator, and returns a private key.
func DHGenerateKey(p, g *big.Int) *DHPrivateKey {
	dh := new(DHPrivateKey)
	dh.p = new(big.Int).Set(p)
	dh.g = new(big.Int).Set(g)

	var err error
	if dh.priv, err = rand.Int(rand.Reader, dh.p); err != nil {
		panic(err)
	}
	dh.pub = new(big.Int).Exp(dh.g, dh.priv, dh.p)

	return dh
}

// Public returns the public key.
func (dh *DHPrivateKey) Public() *big.Int {
	return dh.pub
}

// Secret takes a public key and returns a shared secret.
func (dh *DHPrivateKey) Secret(pub *big.Int) *big.Int {
	return new(big.Int).Exp(pub, dh.priv, dh.p)
}

func main() {
	p, ok := new(big.Int).SetString(strings.Replace(defaultP, "\n", "", -1), 16)
	if !ok {
		panic("invalid parameters")
	}
	g, ok := new(big.Int).SetString(defaultG, 16)
	if !ok {
		panic("invalid parameters")
	}
	alice, bob := DHGenerateKey(p, g), DHGenerateKey(p, g)

	s1 := alice.Secret(bob.Public()).Bytes()
	s2 := bob.Secret(alice.Public()).Bytes()

	if !bytes.Equal(s1, s2) {
		fmt.Fprintln(os.Stderr, "key exchange failed")
		return
	}
	fmt.Printf("%x\n%x\n", sha256.Sum256(s1), sha256.Sum256(s2))
}
