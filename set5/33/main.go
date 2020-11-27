// 33. Implement Diffie-Hellman

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
)

const (
	dhPrime = `ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff`
	dhGenerator = "2"
)

func main() {
	p, err := ParseBigInt(dhPrime, 16)
	if err != nil {
		panic(err)
	}
	g, err := ParseBigInt(dhGenerator, 16)
	if err != nil {
		panic(err)
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

// DHPublicKey represents the public part of a Diffie-Hellman key pair.
type DHPublicKey struct {
	p *big.Int
	g *big.Int
	y *big.Int
}

// DHPrivateKey represents a Diffie-Hellman key pair.
type DHPrivateKey struct {
	DHPublicKey
	x *big.Int
}

// DHGenerateKey generates a private key.
func DHGenerateKey(p, g *big.Int) *DHPrivateKey {
	x, err := rand.Int(rand.Reader, p)
	if err != nil {
		panic(err)
	}
	y := new(big.Int).Exp(g, x, p)

	return &DHPrivateKey{DHPublicKey{p, g, y}, x}
}

// Secret takes a public key and returns a shared secret.
func (priv *DHPrivateKey) Secret(pub *DHPublicKey) []byte {
	return new(big.Int).Exp(pub.y, priv.x, priv.p).Bytes()
}

// Public returns a public key.
func (priv *DHPrivateKey) Public() *DHPublicKey {
	return &priv.DHPublicKey
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
