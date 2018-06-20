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
	defaultPrime = `ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff`
	defaultGenerator = `2`
)

var (
	prime     *big.Int
	generator *big.Int
)

// DHPrivateKey contains a key pair.
type DHPrivateKey struct {
	pub crypto.PublicKey
	n   *big.Int
}

// DHGenerateKey generates a key pair.
func DHGenerateKey() *DHPrivateKey {
	n, err := rand.Int(rand.Reader, prime)
	if err != nil {
		panic(err)
	}
	pub := crypto.PublicKey(new(big.Int).Exp(generator, n, prime))
	return &DHPrivateKey{pub, n}
}

// Public returns the public key.
func (priv *DHPrivateKey) Public() crypto.PublicKey {
	return priv.pub
}

// Secret takes a public key and returns a shared secret.
func (priv *DHPrivateKey) Secret(pub crypto.PublicKey) []byte {
	return new(big.Int).Exp(pub.(*big.Int), priv.n, prime).Bytes()
}

func init() {
	var ok bool
	if prime, ok = new(big.Int).SetString(strings.Replace(defaultPrime, "\n", "", -1), 16); !ok {
		panic("invalid prime")
	}
	if generator, ok = new(big.Int).SetString(defaultGenerator, 16); !ok {
		panic("invalid generator")
	}
}

func main() {
	alice, bob := DHGenerateKey(), DHGenerateKey()

	s1 := alice.Secret(bob.Public())
	s2 := bob.Secret(alice.Public())

	if !bytes.Equal(s1, s2) {
		fmt.Fprintln(os.Stderr, "key exchange failed")
		return
	}
	fmt.Printf("%x\n%x\n", sha256.Sum256(s1), sha256.Sum256(s2))
}
