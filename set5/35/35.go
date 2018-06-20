package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
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

var (
	zero      *big.Int
	one       *big.Int
	p         *big.Int
	pMinusOne *big.Int
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

// dup returns a copy of a buffer.
func dup(buf []byte) []byte {
	return append([]byte{}, buf...)
}

// PKCS7Pad returns a buffer with PKCS#7 padding added.
func PKCS7Pad(buf []byte, blockSize int) []byte {
	if blockSize < 0 || blockSize > 0xff {
		panic("PKCS7Pad: invalid block size")
	}
	// Find the number (and value) of padding bytes.
	n := blockSize - (len(buf) % blockSize)

	return append(dup(buf), bytes.Repeat([]byte{byte(n)}, n)...)
}

// PKCS7Unpad returns a buffer with PKCS#7 padding removed.
func PKCS7Unpad(buf []byte, blockSize int) ([]byte, error) {
	if len(buf) < blockSize {
		return nil, errors.New("PKCS7Unpad: invalid padding")
	}
	// Examine the value of the last byte.
	b := buf[len(buf)-1]
	if int(b) == 0 || int(b) > blockSize ||
		!bytes.Equal(bytes.Repeat([]byte{b}, int(b)), buf[len(buf)-int(b):]) {
		return nil, errors.New("PKCS7Unpad: invalid padding")
	}
	return dup(buf)[:len(buf)-int(b)], nil
}

type bot struct {
	*DHPrivateKey
	key []byte
	iv  []byte
	buf *bytes.Buffer
}

func newBot() *bot {
	return &bot{buf: new(bytes.Buffer)}
}

func (sender *bot) connect(receiver *bot, pub *big.Int) {
	receiver.DHPrivateKey = DHGenerateKey(sender.p, sender.g)

	receiver.key = make([]byte, aes.BlockSize)
	array := sha1.Sum(receiver.Secret(pub))
	copy(receiver.key, array[:])

	receiver.iv = RandomBytes(aes.BlockSize)
}

func (sender *bot) accept(receiver *bot, pub *big.Int) {
	receiver.key = make([]byte, aes.BlockSize)
	array := sha1.Sum(receiver.Secret(pub))
	copy(receiver.key, array[:])

	receiver.iv = RandomBytes(aes.BlockSize)
}

func (sender *bot) send(receiver *bot, iv, msg []byte) {
	c1, err := aes.NewCipher(sender.key)
	if err != nil {
		panic(err)
	}
	msg = PKCS7Pad(msg, c1.BlockSize())
	cipher.NewCBCEncrypter(c1, iv).CryptBlocks(msg, msg)

	c2, err := aes.NewCipher(receiver.key)
	if err != nil {
		panic(err)
	}
	cipher.NewCBCDecrypter(c2, iv).CryptBlocks(msg, msg)
	msg, err = PKCS7Unpad(msg, c2.BlockSize())
	if err != nil {
		panic(err)
	}
	receiver.buf.Write(msg)
}

// equal returns true if n and m are equal.
func equal(n, m *big.Int) bool {
	return n.Cmp(m) == 0
}

func simulateMITM(g *big.Int) {
	alice, bob, mallory := newBot(), newBot(), newBot()
	alice.DHPrivateKey = DHGenerateKey(p, g)

	alice.connect(mallory, alice.Public())
	mallory.connect(bob, alice.Public())

	bob.accept(mallory, bob.Public())
	mallory.accept(alice, bob.Public())

	var secret *big.Int
	switch {
	case equal(g, one):
		secret = one
	case equal(g, p):
		secret = zero
	case equal(g, pMinusOne):
		if equal(alice.Public(), one) || equal(bob.Public(), one) {
			secret = one
		} else {
			secret = pMinusOne
		}
	default:
		panic("simulateMITM: invalid generator")
	}
	array := sha1.Sum(secret.Bytes())
	copy(mallory.key, array[:])

	alice.send(mallory, alice.iv, []byte("hello world"))
	mallory.send(bob, alice.iv, mallory.buf.Bytes())
	fmt.Println(mallory.buf.String())
	mallory.buf.Reset()

	bob.send(mallory, bob.iv, bob.buf.Bytes())
	mallory.send(alice, bob.iv, mallory.buf.Bytes())
	fmt.Println(mallory.buf.String())
}

func init() {
	zero = big.NewInt(0)
	one = big.NewInt(1)

	var ok bool
	if p, ok = new(big.Int).SetString(strings.Replace(defaultP, "\n", "", -1), 16); !ok {
		panic("invalid prime")
	}
	pMinusOne = new(big.Int).Sub(p, one)
}

func main() {
	simulateMITM(one)
	simulateMITM(p)
	simulateMITM(pMinusOne)
}
