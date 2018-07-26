package main

import (
	"bufio"
	"crypto/cipher"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const secret = "ICE"

// xorCipher represents a repeating XOR stream cipher.
type xorCipher struct {
	key []byte
	pos int
}

// NewXORCipher creates a new repeating XOR cipher.
func NewXORCipher(key []byte) cipher.Stream {
	return &xorCipher{key: key}
}

// XORKeyStream encrypts a buffer with repeating XOR.
func (x *xorCipher) XORKeyStream(dst, src []byte) {
	// Panic if dst is smaller than src.
	for i := range src {
		dst[i] = src[i] ^ x.key[x.pos]
		x.pos++
		if x.pos == len(x.key) {
			x.pos = 0
		}
	}
}

// encryptXOR reads plaintext and prints hex-encoded ciphertext.
func encryptXOR(in io.Reader, stream cipher.Stream) error {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		return err
	}
	stream.XORKeyStream(buf, buf)
	fmt.Println(hex.EncodeToString(buf))

	return nil
}

// decryptXOR reads hex-encoded ciphertext and prints plaintext.
func decryptXOR(in io.Reader, stream cipher.Stream) error {
	input := bufio.NewScanner(in)
	var buf []byte
	for input.Scan() {
		line, err := hex.DecodeString(input.Text())
		if err != nil {
			return err
		}
		buf = append(buf, line...)
	}
	if err := input.Err(); err != nil {
		return err
	}
	stream.XORKeyStream(buf, buf)
	fmt.Print(string(buf))

	return nil
}

func main() {
	var (
		d  bool
		fn func(io.Reader, cipher.Stream) error
	)
	flag.BoolVar(&d, "d", false, "decrypt")
	flag.Parse()
	if d {
		fn = decryptXOR
	} else {
		fn = encryptXOR
	}
	files := flag.Args()
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		stream := NewXORCipher([]byte(secret))
		if err := fn(os.Stdin, stream); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		// Since the stream is stateful, we have to re-initialize it.
		stream := NewXORCipher([]byte(secret))
		if err := fn(f, stream); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
