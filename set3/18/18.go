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

// encryptAndPrint reads plaintext and prints base64-encoded ciphertext.
func encryptAndPrint(in io.Reader, stream cipher.Stream) {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	stream.XORKeyStream(buf, buf)
	fmt.Println(base64.StdEncoding.EncodeToString(buf))
}

// decryptAndPrint reads base64-encoded ciphertext and prints plaintext.
func decryptAndPrint(in io.Reader, stream cipher.Stream) {
	in = base64.NewDecoder(base64.StdEncoding, in)
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	stream.XORKeyStream(buf, buf)
	fmt.Println(string(buf))
}

var e = flag.Bool("e", false, "encrypt")

func main() {
	c, err := aes.NewCipher([]byte(secret))
	if err != nil {
		panic(err)
	}
	iv := make([]byte, c.BlockSize())
	stream := NewCTR(c, iv)

	flag.Parse()
	files := flag.Args()
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if *e {
			encryptAndPrint(os.Stdin, stream)
		} else {
			decryptAndPrint(os.Stdin, stream)
		}
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if *e {
			encryptAndPrint(f, stream)
		} else {
			decryptAndPrint(f, stream)
		}
		f.Close()
	}
}
