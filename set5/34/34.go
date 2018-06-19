package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha1"
	"math/big"
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
func (dh *DHPrivateKey) Secret(pub *big.Int) []byte {
	return new(big.Int).Exp(pub, dh.priv, dh.p).Bytes()
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	res := make([]byte, n)
	if _, err := rand.Read(res); err != nil {
		panic(err)
	}
	return res
}

type bot struct {
	dh  *DHPrivateKey
	key []byte
	iv  []byte
	buf *bytes.Buffer
}

func (sender *bot) Connect(receiver *bot, pub *big.Int) {
	receiver.dh = DHGenerateKey(sender.dh.p, sender.dh.g)

	receiver.key = make([]byte, aes.BlockSize)
	array := sha1.Sum(receiver.dh.Secret(pub))
	copy(receiver.key, array[:])

	receiver.iv = RandomBytes(aes.BlockSize)
}

func (sender *bot) Accept(receiver *bot, pub *big.Int) {
	receiver.key = make([]byte, aes.BlockSize)
	array := sha1.Sum(receiver.dh.Secret(pub))
	copy(receiver.key, array[:])

	receiver.iv = RandomBytes(aes.BlockSize)
}

func (sender *bot) Send(receiver *bot, iv, msg []byte) {
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
	alice, bob := new(bot), new(bot)
	alice.dh = DHGenerateKey(p, g)

	alice.Connect(bob, alice.dh.Public())
	bob.Accept(alice, bob.dh.Public())
}
