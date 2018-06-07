package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"os"
)

// AES always has a block size of 128 bits (16 bytes).
const aesBlockSize = 16

// mac contains a hash and secret key.
type mac struct {
	hash.Hash
	key []byte
}

// NewMAC takes a hash and key, and returns a new MAC hash.
func NewMAC(h func() hash.Hash, key []byte) hash.Hash {
	m := mac{h(), key}
	m.Reset()
	return m
}

// Reset resets the hash.
func (m mac) Reset() {
	m.Hash.Reset()
	if n, err := m.Hash.Write(m.key); n != len(m.key) {
		panic("Reset: write error")
	} else if err != nil {
		panic(fmt.Sprintf("Reset: %s", err.Error()))
	}
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	res := make([]byte, n)
	if _, err := rand.Read(res); err != nil {
		panic(fmt.Sprintf("RandomBytes: %s", err.Error()))
	}
	return res
}

// printHash prints a name and hex-encoded hash value.
func printHash(s string, buf []byte) {
	fmt.Printf("%-19s%x\n", s, buf)
}

// readAndPrintHashes reads input and prints the MAC and SHA-1 checksum of the key and data.
func readAndPrintHashes(in io.Reader, h hash.Hash, key []byte) {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	h.Reset()
	if n, err := h.Write(buf); n != len(buf) {
		fmt.Fprintln(os.Stderr, "write error")
		return
	} else if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	mac := h.Sum([]byte{})
	array := sha1.Sum(append(key, buf...))
	sum := array[:]
	if !bytes.Equal(mac, sum) {
		fmt.Fprintln(os.Stderr, "incorrect hash")
		return
	}
	printHash("mac:", mac)
	printHash("sha1(key+message):", sum)
}

func main() {
	key := RandomBytes(aesBlockSize)
	h := NewMAC(sha1.New, key)

	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		readAndPrintHashes(os.Stdin, h, key)
		return
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		readAndPrintHashes(f, h, key)
		f.Close()
	}
}
