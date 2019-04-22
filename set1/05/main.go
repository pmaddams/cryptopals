// 5. Implement repeating-key XOR

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

func main() {
	var (
		d  bool
		fn func(io.Reader, cipher.Stream) error
	)
	flag.BoolVar(&d, "d", false, "decrypt")
	flag.Parse()
	if d {
		fn = decrypt
	} else {
		fn = encrypt
	}
	files := flag.Args()
	if len(files) == 0 {
		stream := NewXORCipher([]byte(secret))
		if err := fn(os.Stdin, stream); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		stream := NewXORCipher([]byte(secret))
		if err := fn(f, stream); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}

// encrypt reads plaintext and prints hex-encoded ciphertext.
func encrypt(in io.Reader, stream cipher.Stream) error {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		return err
	}
	stream.XORKeyStream(buf, buf)
	fmt.Println(hex.EncodeToString(buf))

	return nil
}

// decrypt reads hex-encoded ciphertext and prints plaintext.
func decrypt(in io.Reader, stream cipher.Stream) error {
	var buf []byte

	input := bufio.NewScanner(in)
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
