package main

import (
	"bytes"
	"crypto"
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

// DHPrivateKey contains a prime, generator, and key pair.
type DHPrivateKey struct {
	p   *big.Int
	g   *big.Int
	n   *big.Int
	pub crypto.PublicKey
}

// DHGenerateKey generates a private key.
func DHGenerateKey(p, g *big.Int) *DHPrivateKey {
	n, err := rand.Int(rand.Reader, p)
	if err != nil {
		panic(err)
	}
	pub := crypto.PublicKey(new(big.Int).Exp(g, n, p))
	return &DHPrivateKey{p, g, n, pub}
}

// Public returns the public key.
func (priv *DHPrivateKey) Public() crypto.PublicKey {
	return priv.pub
}

// Secret takes a public key and returns a shared secret.
func (priv *DHPrivateKey) Secret(pub crypto.PublicKey) []byte {
	return new(big.Int).Exp(pub.(*big.Int), priv.n, priv.p).Bytes()
}

func main() {
	p, ok := new(big.Int).SetString(strings.Replace(defaultP, "\n", "", -1), 16)
	if !ok || !p.ProbablyPrime(0) {
		panic("invalid prime")
	}
	g, ok := new(big.Int).SetString(defaultG, 16)
	if !ok {
		panic("invalid generator")
	}
	alice, bob := DHGenerateKey(p, g), DHGenerateKey(p, g)

	s1 := alice.Secret(bob.Public())
	s2 := bob.Secret(alice.Public())

	if !bytes.Equal(s1, s2) {
		fmt.Fprintln(os.Stderr, "key exchange failed")
		return
	}
	fmt.Printf("%x\n%x\n", sha256.Sum256(s1), sha256.Sum256(s2))
}
