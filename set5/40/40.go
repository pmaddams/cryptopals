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

// RSAGenerateKey generates a private key.
func RSAGenerateKey(exponent, bits int) (*RSAPrivateKey, error) {
	e := big.NewInt(int64(exponent))
	if exponent < 3 || !e.ProbablyPrime(0) {
		return nil, errors.New("RSAGenerateKey: invalid exponent")
	}
Retry:
	p, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	q, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	if q.Cmp(p) == 0 {
		goto Retry
	}
	pMinusOne := new(big.Int).Sub(p, one)
	qMinusOne := new(big.Int).Sub(q, one)
	totient := pMinusOne.Mul(pMinusOne, qMinusOne)
	d := new(big.Int)
	if gcd := new(big.Int).GCD(d, nil, e, totient); gcd.Cmp(one) != 0 {
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

// RSAEncrypt takes an encrypted buffer and returns a decrypted buffer.
func RSAEncrypt(pub *RSAPublicKey, buf []byte) ([]byte, error) {
	if len(buf) > pub.n.BitLen()/8 {
		return nil, errors.New("RSAEncrypt: buffer too large")
	}
	z := new(big.Int).SetBytes(buf)
	z = z.Exp(z, pub.e, pub.n)
	return z.Bytes(), nil
}

// RSADecrypt takes a decrypted buffer and returns an encrypted buffer.
func RSADecrypt(priv *RSAPrivateKey, buf []byte) ([]byte, error) {
	if len(buf) > priv.n.BitLen()/8 {
		return nil, errors.New("RSADecrypt: buffer too large")
	}
	z := new(big.Int).SetBytes(buf)
	z = z.Exp(z, priv.d, priv.n)
	return z.Bytes(), nil
}

// rsaBroadcaster returns an RSA broadcast function.
func rsaBroadcaster(s string) func() (*RSAPublicKey, []byte) {
	return func() (*RSAPublicKey, []byte) {
		priv, err := RSAGenerateKey(3, 8*(len(s)+1))
		if err != nil {
			panic(err)
		}
		pub := &priv.RSAPublicKey
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
	for prev.Cmp(guess) != 0 {
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

// crtDecrypt takes an RSA broadcast function and returns the plaintext
// using three different public keys and the Chinese remainder theorem.
func crtDecrypt(broadcast func() (*RSAPublicKey, []byte)) []byte {
	pubs := []*RSAPublicKey{}
	bufs := [][]byte{}
	for i := 0; i < 3; i++ {
	Retry:
		pub, buf := broadcast()
		for j := 0; j < i; j++ {
			// Make sure the moduli are different.
			if pub.n.Cmp(pubs[j].n) == 0 {
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
	n23 := new(big.Int).Mul(n2, n3)
	n13 := new(big.Int).Mul(n1, n3)
	n12 := new(big.Int).Mul(n1, n2)
	n123 := new(big.Int).Mul(n1, n23)

	fst := new(big.Int).ModInverse(n23, n1)
	fst.Mul(fst, n23)
	fst.Mul(fst, c1)

	snd := new(big.Int).ModInverse(n13, n2)
	snd.Mul(snd, n13)
	snd.Mul(snd, c2)

	thd := new(big.Int).ModInverse(n12, n3)
	thd.Mul(thd, n12)
	thd.Mul(thd, c3)

	fst.Add(fst, snd.Add(snd, thd))
	fst.Mod(fst, n123)

	return Cbrt(fst).Bytes()
}

// printCRT reads lines of input, encrypts them, and prints the decrypted plaintext.
func printCRT(in io.Reader) error {
	input := bufio.NewScanner(in)
	for input.Scan() {
		broadcast := rsaBroadcaster(input.Text())
		buf := crtDecrypt(broadcast)
		fmt.Println(string(buf))
	}
	return input.Err()
}

func main() {
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := printCRT(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := printCRT(f); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
