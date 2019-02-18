// 40. Implement an E=3 RSA Broadcast attack

package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
)

var (
	one   = big.NewInt(1)
	two   = big.NewInt(2)
	three = big.NewInt(3)
)

// RSAPublicKey represents the public part of an RSA key pair.
type RSAPublicKey struct {
	n *big.Int
	e *big.Int
}

// RSAPrivateKey represents an RSA key pair.
type RSAPrivateKey struct {
	RSAPublicKey
	d *big.Int
}

// equal returns true if two arbitrary-precision integers are equal.
func equal(z1, z2 *big.Int) bool {
	return z1.Cmp(z2) == 0
}

// RSAGenerateKey generates a private key.
func RSAGenerateKey(exponent, bits int) (*RSAPrivateKey, error) {
	e := big.NewInt(int64(exponent))
	if exponent < 3 || !e.ProbablyPrime(0) {
		return nil, errors.New("RSAGenerateKey: invalid exponent")
	}
Retry:
	p, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, err
	}
	q, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, err
	}
	if equal(p, q) {
		goto Retry
	}
	pMinusOne := new(big.Int).Sub(p, one)
	qMinusOne := new(big.Int).Sub(q, one)
	totient := pMinusOne.Mul(pMinusOne, qMinusOne)
	d := new(big.Int)
	if gcd := new(big.Int).GCD(d, nil, e, totient); !equal(gcd, one) {
		goto Retry
	}
	if d.Sign() < 0 {
		d.Add(d, totient)
	}
	return &RSAPrivateKey{
		RSAPublicKey{
			n: p.Mul(p, q),
			e: e,
		},
		d,
	}, nil
}

// Public returns a public key.
func (priv *RSAPrivateKey) Public() *RSAPublicKey {
	return &priv.RSAPublicKey
}

// size returns the size of an arbitrary-precision integer in bytes.
func size(z *big.Int) int {
	return (z.BitLen() + 7) / 8
}

// copyR copies a source buffer to the right of a destination buffer.
func copyR(dst, src []byte) int {
	return copy(dst[len(dst)-len(src):], src)
}

// RSAEncrypt takes a public key and plaintext, and returns ciphertext.
func RSAEncrypt(pub *RSAPublicKey, buf []byte) ([]byte, error) {
	z := new(big.Int).SetBytes(buf)
	if z.Cmp(pub.n) > 0 {
		return nil, errors.New("RSAEncrypt: buffer too large")
	}
	z.Exp(z, pub.e, pub.n)

	res := make([]byte, size(pub.n))
	copyR(res, z.Bytes())

	return res, nil
}

// RSADecrypt takes a private key and ciphertext, and returns plaintext.
func RSADecrypt(priv *RSAPrivateKey, buf []byte) ([]byte, error) {
	z := new(big.Int).SetBytes(buf)
	if z.Cmp(priv.n) > 0 {
		return nil, errors.New("RSADecrypt: buffer too large")
	}
	z.Exp(z, priv.d, priv.n)

	res := make([]byte, size(priv.n))
	copyR(res, z.Bytes())

	return res, nil
}

// rsaBroadcaster returns an RSA broadcast function.
func rsaBroadcaster(s string) func() (*RSAPublicKey, []byte) {
	return func() (*RSAPublicKey, []byte) {
		priv, err := RSAGenerateKey(3, 8*(len(s)+2))
		if err != nil {
			panic(err)
		}
		pub := priv.Public()
		buf, err := RSAEncrypt(pub, []byte(s))
		if err != nil {
			panic(err)
		}
		return pub, buf
	}
}

// Cbrt returns the cube root of the given integer using successive approximations.
func Cbrt(z *big.Int) *big.Int {
	prev := new(big.Int)
	guess := new(big.Int).Set(z)
	for !equal(prev, guess) {
		prev.Set(guess)
		guess.Mul(guess, guess)
		guess.Div(z, guess)
		guess.Add(guess, prev)
		guess.Add(guess, prev)
		guess.Div(guess, three)

		// Average the new and previous guesses to prevent oscillation.
		guess.Add(guess, prev)
		guess.Div(guess, two)
	}
	return guess
}

// breakBroadcast takes an RSA broadcast function and returns the decrypted plaintext.
func breakBroadcast(broadcast func() (*RSAPublicKey, []byte)) []byte {
	pubs := []*RSAPublicKey{}
	bufs := [][]byte{}
	for i := 0; i < 3; i++ {
	Retry:
		pub, buf := broadcast()
		for j := 0; j < i; j++ {
			// Make sure the moduli are different.
			if equal(pub.n, pubs[j].n) {
				goto Retry
			}
		}
		pubs = append(pubs, pub)
		bufs = append(bufs, buf)
	}
	c1 := new(big.Int).SetBytes(bufs[0])
	c2 := new(big.Int).SetBytes(bufs[1])
	c3 := new(big.Int).SetBytes(bufs[2])

	n1, n2, n3 := pubs[0].n, pubs[1].n, pubs[2].n
	z := new(big.Int)

	n23 := z.Mul(n2, n3)
	fst := new(big.Int).ModInverse(n23, n1)
	fst.Mul(fst, n23)
	fst.Mul(fst, c1)

	n13 := z.Mul(n1, n3)
	snd := new(big.Int).ModInverse(n13, n2)
	snd.Mul(snd, n13)
	snd.Mul(snd, c2)

	n12 := z.Mul(n1, n2)
	thd := new(big.Int).ModInverse(n12, n3)
	thd.Mul(thd, n12)
	thd.Mul(thd, c3)

	n123 := z.Mul(n12, n3)
	cube := fst.Add(fst, snd.Add(snd, thd))
	cube.Mod(cube, n123)

	return Cbrt(cube).Bytes()
}

// decryptBroadcast reads lines of text, encrypts them, and prints the decrypted plaintext.
func decryptBroadcast(in io.Reader) error {
	input := bufio.NewScanner(in)
	for input.Scan() {
		broadcast := rsaBroadcaster(input.Text())
		buf := breakBroadcast(broadcast)
		fmt.Println(string(buf))
	}
	return input.Err()
}

func main() {
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := decryptBroadcast(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := decryptBroadcast(f); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
