package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	weak "math/rand"
	"os"
	"time"
)

// mac represents a hash for a secret-prefix message authentication code.
type mac struct {
	hash.Hash
	key []byte
}

// NewMAC takes a hash and key, and returns a new MAC hash.
func NewMAC(f func() hash.Hash, key []byte) hash.Hash {
	m := mac{f(), key}
	m.Reset()
	return m
}

// Reset resets the hash.
func (m mac) Reset() {
	m.Hash.Reset()
	if _, err := m.Hash.Write(m.key); err != nil {
		panic(err)
	}
}

// RandomRange returns a pseudo-random non-negative integer in [lo, hi].
// The output should not be used in a security-sensitive context.
func RandomRange(lo, hi int) int {
	if lo < 0 || lo > hi {
		panic("RandomRange: invalid range")
	}
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	return lo + weak.Intn(hi-lo+1)
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	res := make([]byte, n)
	if _, err := rand.Read(res); err != nil {
		panic(err)
	}
	return res
}

// readAndPrintMAC reads input and prints the MAC and SHA-1(key + message).
func readAndPrintMAC(in io.Reader, mac hash.Hash, key []byte) {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	mac.Reset()
	if _, err := mac.Write(buf); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	sum1 := mac.Sum([]byte{})
	array := sha1.Sum(append(key, buf...))
	sum2 := array[:]
	if !bytes.Equal(sum1, sum2) {
		fmt.Fprintln(os.Stderr, "invalid MAC")
		return
	}
	fmt.Printf("%x\n%x\n", sum1, sum2)
}

func main() {
	key := RandomBytes(RandomRange(8, 64))
	mac := NewMAC(sha1.New, key)

	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		readAndPrintMAC(os.Stdin, mac, key)
		return
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		readAndPrintMAC(f, mac, key)
		f.Close()
	}
}
