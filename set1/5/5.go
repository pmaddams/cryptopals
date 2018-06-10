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

// xorCipher is a repeating XOR stream cipher.
type xorCipher struct {
	key []byte
	pos int
}

// NewXORCipher creates a new repeating XOR cipher.
func NewXORCipher(key []byte) cipher.Stream {
	return &xorCipher{key, 0}
}

// XORKeyStream encrypts a buffer with repeating XOR.
func (stream *xorCipher) XORKeyStream(dst, src []byte) {
	// Panic if dst is smaller than src.
	for i := range src {
		dst[i] = src[i] ^ stream.key[stream.pos]
		stream.pos++

		// At the end of the key, reset position.
		if stream.pos == len(stream.key) {
			stream.pos = 0
		}
	}
}

// encryptAndPrint reads plaintext and prints hex-encoded ciphertext.
func encryptAndPrint(in io.Reader, stream cipher.Stream) {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	stream.XORKeyStream(buf, buf)
	fmt.Println(hex.EncodeToString(buf))
}

// decryptAndPrint reads hex-encoded ciphertext and prints plaintext.
func decryptAndPrint(in io.Reader, stream cipher.Stream) {
	input := bufio.NewScanner(in)
	var buf []byte
	for input.Scan() {
		line, err := hex.DecodeString(input.Text())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		buf = append(buf, line...)
	}
	if err := input.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	stream.XORKeyStream(buf, buf)
	fmt.Print(string(buf))
}

var d = flag.Bool("d", false, "decrypt")

func main() {
	flag.Parse()
	files := flag.Args()
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		stream := NewXORCipher([]byte(secret))
		if *d {
			decryptAndPrint(os.Stdin, stream)
		} else {
			encryptAndPrint(os.Stdin, stream)
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
		if *d {
			decryptAndPrint(f, stream)
		} else {
			encryptAndPrint(f, stream)
		}
		f.Close()
	}
}
