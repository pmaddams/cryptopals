package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const secret = "YELLOW SUBMARINE"

// BytesToUint64s converts a buffer to a slice of unsigned 64-bit integers.
func BytesToUint64s(buf []byte) []uint64 {
	nums := make([]uint64, len(buf)/8)
	for i := range nums {
		nums[i] = binary.LittleEndian.Uint64(buf[8*i:])
	}
	return nums
}

// Uint64sToBytes converts a slice of unsigned 64-bit integers to a buffer.
func Uint64sToBytes(nums []uint64) []byte {
	buf := make([]byte, len(nums)*8)
	for i := range nums {
		binary.LittleEndian.PutUint64(buf[8*i:], nums[i])
	}
	return buf
}

// ctr represents a CTR mode stream cipher.
type ctr struct {
	c   cipher.Block
	ctr []uint64
	pos int
}

// NewCTR returns a CTR mode stream cipher.
func NewCTR(c cipher.Block, iv []byte) cipher.Stream {
	if c.BlockSize() != len(iv) {
		panic("NewCTR: initialization vector length must equal block size")
	}
	return ctr{c, BytesToUint64s(iv), 0}
}

// inc increments the counter.
func (stream ctr) inc() {
	for i := len(stream.ctr) - 1; i >= 0; i-- {
		stream.ctr[i]++
		if stream.ctr[i] != 0 {
			break
		}
	}
}

// XORKeyStream encrypts a buffer with the CTR keystream.
func (stream ctr) XORKeyStream(dst, src []byte) {
	for {
		tmp := make([]byte, stream.c.BlockSize())
		stream.c.Encrypt(tmp, Uint64sToBytes(stream.ctr))

		// Panic if dst is smaller than src.
		for len(src) > 0 && stream.pos < stream.c.BlockSize() {
			dst[0] = src[0] ^ tmp[stream.pos]
			dst = dst[1:]
			src = src[1:]
			stream.pos++
		}
		if stream.pos == stream.c.BlockSize() {
			stream.pos = 0
			stream.inc()
		} else {
			break
		}
	}
}

// encryptCTR reads plaintext and prints base64-encoded ciphertext.
func encryptCTR(in io.Reader, stream cipher.Stream) error {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		return err
	}
	stream.XORKeyStream(buf, buf)
	fmt.Println(base64.StdEncoding.EncodeToString(buf))

	return nil
}

// decryptCTR reads base64-encoded ciphertext and prints plaintext.
func decryptCTR(in io.Reader, stream cipher.Stream) error {
	in = base64.NewDecoder(base64.StdEncoding, in)
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		return err
	}
	stream.XORKeyStream(buf, buf)
	fmt.Println(string(buf))

	return nil
}

func main() {
	c, err := aes.NewCipher([]byte(secret))
	if err != nil {
		panic(err)
	}
	iv := make([]byte, c.BlockSize())
	stream := NewCTR(c, iv)
	var (
		e  bool
		fn func(io.Reader, cipher.Stream) error
	)
	flag.BoolVar(&e, "e", false, "encrypt")
	flag.Parse()
	if e {
		fn = encryptCTR
	} else {
		fn = decryptCTR
	}
	files := flag.Args()
	// If no files are specified, read from standard input.
	if len(files) == 0 {
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
		if err := fn(f, stream); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
