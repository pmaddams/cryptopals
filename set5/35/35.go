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
	dhDefaultP = `ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff`
	dhDefaultG = `2`
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

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

// Public returns a public key.
func (priv *DHPrivateKey) Public() *DHPublicKey {
	return &priv.DHPublicKey
}

// Secret takes a public key and returns a shared secret.
func (priv *DHPrivateKey) Secret(pub *DHPublicKey) []byte {
	return new(big.Int).Exp(pub.y, priv.x, priv.p).Bytes()
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
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
	errInvalidPadding := errors.New("PKCS7Unpad: invalid padding")
	if len(buf) < blockSize {
		return nil, errInvalidPadding
	}
	// Examine the value of the last byte.
	b := buf[len(buf)-1]
	if int(b) == 0 || int(b) > blockSize ||
		!bytes.Equal(bytes.Repeat([]byte{b}, int(b)), buf[len(buf)-int(b):]) {
		return nil, errInvalidPadding
	}
	return dup(buf)[:len(buf)-int(b)], nil
}

// bot is a simulated agent that participates in Diffie-Hellman key exchange.
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
func (sender *bot) connect(receiver *bot, pub *DHPublicKey) {
	receiver.DHPrivateKey = DHGenerateKey(sender.p, sender.g)

	receiver.key = make([]byte, aes.BlockSize)
	array := sha1.Sum(receiver.Secret(pub))
	copy(receiver.key, array[:])

	receiver.iv = RandomBytes(aes.BlockSize)
}

// accept completes Diffie-Hellman key exchange from one bot to another.
func (sender *bot) accept(receiver *bot, pub *DHPublicKey) {
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

// equal returns true if two arbitrary-precision integers are equal.
func equal(z1, z2 *big.Int) bool {
	return z1.Cmp(z2) == 0
}

// simulateMITM simulates a man-in-the-middle attack.
func simulateMITM(p, g *big.Int) {
	alice, bob, mallory := newBot(), newBot(), newBot()
	alice.DHPrivateKey = DHGenerateKey(p, g)

	alice.connect(mallory, alice.Public())
	mallory.connect(bob, alice.Public())

	bob.accept(mallory, bob.Public())
	mallory.accept(alice, bob.Public())

	var secret *big.Int
	if equal(g, one) {
		secret = one
	} else if equal(g, p) {
		secret = zero
	} else if pMinusOne := new(big.Int).Sub(p, one); equal(g, pMinusOne) {
		if equal(alice.y, one) || equal(bob.y, one) {
			secret = one
		} else {
			secret = pMinusOne
		}
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

// parseBigInt converts a string to an arbitrary-precision integer.
func parseBigInt(s string, base int) (*big.Int, error) {
	if base < 0 || base > 16 {
		return nil, errors.New("parseBigInt: invalid base")
	}
	s = strings.Replace(s, "\n", "", -1)
	z, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, errors.New("parseBigInt: invalid string")
	}
	return z, nil
}

func main() {
	p, err := parseBigInt(dhDefaultP, 16)
	if err != nil {
		panic(err)
	}
	simulateMITM(p, one)
	simulateMITM(p, p)
	simulateMITM(p, new(big.Int).Sub(p, one))
}
