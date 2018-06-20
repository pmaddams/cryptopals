package main

import (
	"bytes"
	"crypto"
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
	zero          *big.Int
	one           *big.Int
	prime         *big.Int
	primeMinusOne *big.Int
	generator     *big.Int
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

// bot contains contains data for simulating a man-in-the-middle attack.
type bot struct {
	*DHPrivateKey
	key []byte
	iv  []byte
	buf *bytes.Buffer
}

// newBot returns a bot.
func newBot() *bot {
	return &bot{buf: new(bytes.Buffer)}
}

// connect initiates Diffie-Hellman key exchange from one bot to another.
func (sender *bot) connect(receiver *bot, pub crypto.PublicKey) {
	receiver.DHPrivateKey = DHGenerateKey()

	receiver.key = make([]byte, aes.BlockSize)
	array := sha1.Sum(receiver.Secret(pub))
	copy(receiver.key, array[:])

	receiver.iv = RandomBytes(aes.BlockSize)
}

// accept completes Diffie-Hellman key exchange from one bot to another.
func (sender *bot) accept(receiver *bot, pub crypto.PublicKey) {
	receiver.key = make([]byte, aes.BlockSize)
	array := sha1.Sum(receiver.Secret(pub))
	copy(receiver.key, array[:])

	receiver.iv = RandomBytes(aes.BlockSize)
}

// send sends a message encrypted with AES-CBC from one bot to another.
func (sender *bot) send(receiver *bot, iv, buf []byte) {
	c1, err := aes.NewCipher(sender.key)
	if err != nil {
		panic(err)
	}
	buf = PKCS7Pad(buf, c1.BlockSize())
	cipher.NewCBCEncrypter(c1, iv).CryptBlocks(buf, buf)

	c2, err := aes.NewCipher(receiver.key)
	if err != nil {
		panic(err)
	}
	cipher.NewCBCDecrypter(c2, iv).CryptBlocks(buf, buf)
	buf, err = PKCS7Unpad(buf, c2.BlockSize())
	if err != nil {
		panic(err)
	}
	receiver.buf.Write(buf)
}

// equal returns true if n and m are equal.
func equal(n, m *big.Int) bool {
	return n.Cmp(m) == 0
}

func simulateMITM() {
	alice, bob, mallory := newBot(), newBot(), newBot()
	alice.DHPrivateKey = DHGenerateKey()

	alice.connect(mallory, alice.Public())
	mallory.connect(bob, alice.Public())

	bob.accept(mallory, bob.Public())
	mallory.accept(alice, bob.Public())

	var secret *big.Int
	switch {
	case equal(generator, one):
		secret = one
	case equal(generator, prime):
		secret = zero
	case equal(generator, primeMinusOne):
		if equal(alice.Public().(*big.Int), one) ||
			equal(bob.Public().(*big.Int), one) {
			secret = one
		} else {
			secret = primeMinusOne
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
	if prime, ok = new(big.Int).SetString(strings.Replace(defaultPrime, "\n", "", -1), 16); !ok {
		panic("invalid prime")
	}
	primeMinusOne = new(big.Int).Sub(prime, one)
	if generator, ok = new(big.Int).SetString(defaultGenerator, 16); !ok {
		panic("invalid generator")
	}
}

func main() {
	generator = one
	simulateMITM()

	generator = prime
	simulateMITM()

	generator = primeMinusOne
	simulateMITM()
}
