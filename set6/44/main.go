// 44. DSA nonce recovery from repeated nonce

package main

import (
	"bufio"
	"bytes"
	"crypto/dsa"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
)

const (
	dsaPrime = `800000000000000089e1855218a0e7dac38136ffafa72eda7
859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
1a584471bb1`
	dsaSubprime  = "f4f47f05794b256174bba6e9b396a7707e563c5b"
	dsaGenerator = `5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
0f5b64c36b625a097f1651fe775323556fe00b3608c887892
878480e99041be601a62166ca6894bdd41a7054ec89f756ba
9fc95302291`
)

func main() {
	p, err := ParseBigInt(dsaPrime, 16)
	if err != nil {
		panic(err)
	}
	q, err := ParseBigInt(dsaSubprime, 16)
	if err != nil {
		panic(err)
	}
	g, err := ParseBigInt(dsaGenerator, 16)
	if err != nil {
		panic(err)
	}
	y, err := ParseBigInt(`2d026f4bf30195ede3a088da85e398ef869611d0f68f07
13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
2971c3de5084cce04a2e147821`, 16)
	if err != nil {
		panic(err)
	}
	pub := &dsa.PublicKey{
		Parameters: dsa.Parameters{
			P: p,
			Q: q,
			G: g,
		},
		Y: y,
	}
	f, err := os.Open("44.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	msgs, err := readMessages(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	for pair := range messagePairs(msgs) {
		k := possibleK(pair, pub)
		msg := pair.fst
		if breakDSA(pub, msg.sum, msg.r, msg.s, k) != nil {
			fmt.Println("success")
			return
		}
	}
}

// message represents a message signed with DSA.
type message struct {
	sum []byte
	r   *big.Int
	s   *big.Int
}

// readMessages reads all messages from the input.
func readMessages(in io.Reader) ([]*message, error) {
	var msgs []*message
	input := bufio.NewScanner(in)
	for {
		if msg, err := scanMessage(input); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		} else {
			msgs = append(msgs, msg)
		}
	}
	return msgs, input.Err()
}

// scanMessage reads lines matching the message format and returns the message.
func scanMessage(input *bufio.Scanner) (*message, error) {
	msg := new(message)
	var (
		s   string
		err error
	)
	if s, err = scanAfterPrefix(input, "msg: "); err != nil {
		return nil, err
	}
	array := sha1.Sum([]byte(s))
	if s, err = scanAfterPrefix(input, "s: "); err != nil {
		return nil, err
	}
	if msg.s, err = ParseBigInt(s, 10); err != nil {
		return nil, err
	}
	if s, err = scanAfterPrefix(input, "r: "); err != nil {
		return nil, err
	}
	if msg.r, err = ParseBigInt(s, 10); err != nil {
		return nil, err
	}
	if s, err = scanAfterPrefix(input, "m: "); err != nil {
		return nil, err
	}
	if msg.sum, err = hex.DecodeString(s); err != nil {
		return nil, err
	} else if !bytes.Equal(msg.sum, array[:]) {
		return nil, errors.New("scanMessage: invalid checksum")
	}
	return msg, nil
}

// scanAfterPrefix reads a line and returns the string after a prefix.
func scanAfterPrefix(input *bufio.Scanner, prefix string) (string, error) {
	if !input.Scan() {
		return "", io.EOF
	}
	if !strings.HasPrefix(input.Text(), prefix) {
		return "", errors.New("scanAfterPrefix: invalid input")
	}
	return input.Text()[len(prefix):], input.Err()
}

// messagePair represents a pair of messages.
type messagePair struct {
	fst *message
	snd *message
}

// messagePairs returns a channel that yields all pairs of messages.
func messagePairs(msgs []*message) <-chan messagePair {
	ch := make(chan messagePair)
	go func() {
		for i := 0; i < len(msgs)-1; i++ {
			for j := i + 1; j < len(msgs); j++ {
				ch <- messagePair{msgs[i], msgs[j]}
			}
		}
		close(ch)
	}()
	return ch
}

// possibleK returns a possible k value for a pair of messages.
func possibleK(pair messagePair, pub *dsa.PublicKey) *big.Int {
	z1 := new(big.Int).SetBytes(pair.fst.sum)
	z2 := new(big.Int).SetBytes(pair.snd.sum)

	z1.Sub(z1, z2)
	z2.Sub(pair.fst.s, pair.snd.s)
	z2.ModInverse(z2, pub.Q)
	k := z1.Mul(z1, z2)

	return k.Mod(k, pub.Q)
}

// breakDSA returns the private key used to sign a checksum.
func breakDSA(pub *dsa.PublicKey, sum []byte, r, s, k *big.Int) *dsa.PrivateKey {
	z1 := new(big.Int).Mul(s, k)
	z2 := new(big.Int).SetBytes(sum)
	z1.Sub(z1, z2)
	z2.ModInverse(r, pub.Q)

	x := z1.Mul(z1, z2)
	x.Mod(x, pub.Q)

	y := z2.Exp(pub.G, x, pub.P)
	if !equal(y, pub.Y) {
		return nil
	}
	return &dsa.PrivateKey{
		PublicKey: *pub,
		X:         x,
	}
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

// equal returns true if two arbitrary-precision integers are equal.
func equal(z1, z2 *big.Int) bool {
	return z1.Cmp(z2) == 0
}
