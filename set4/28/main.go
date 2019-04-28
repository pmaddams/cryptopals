// 28. Implement a SHA-1 keyed MAC

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	weak "math/rand"
	"os"
	"time"
)

func init() { weak.Seed(time.Now().UnixNano()) }

func main() {
	key := RandomBytes(RandomInRange(8, 64))
	mac := NewMAC(sha1.New, key)

	files := os.Args[1:]
	if len(files) == 0 {
		if err := printMAC(os.Stdin, mac, key); err != nil {
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
		if err := printMAC(f, mac, key); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}

// printMAC reads input and prints the MAC and SHA-1(key + message).
func printMAC(in io.Reader, mac hash.Hash, key []byte) error {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		return err
	}
	mac.Reset()
	if _, err := mac.Write(buf); err != nil {
		return err
	}
	sum1 := mac.Sum([]byte{})
	array := sha1.Sum(append(key, buf...))
	sum2 := array[:]
	if !bytes.Equal(sum1, sum2) {
		return errors.New("printMAC: invalid MAC")
	}
	fmt.Printf("%x\n%x\n", sum1, sum2)

	return nil
}

// mac represents a hash for a secret-prefix message authentication code.
type mac struct {
	hash.Hash
	key []byte
}

// NewMAC takes a hash and key, and returns a new MAC hash.
func NewMAC(fn func() hash.Hash, key []byte) hash.Hash {
	x := mac{fn(), key}
	x.Reset()
	return x
}

// Reset resets the hash.
func (x mac) Reset() {
	x.Hash.Reset()
	if _, err := x.Hash.Write(x.key); err != nil {
		panic(err)
	}
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

// RandomInRange returns a pseudo-random non-negative integer in [lo, hi].
// The output should not be used in a security-sensitive context.
func RandomInRange(lo, hi int) int {
	if lo < 0 || lo > hi {
		panic("RandomInRange: invalid range")
	}
	return lo + weak.Intn(hi-lo+1)
}
