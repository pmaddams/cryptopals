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

// AES always has a block size of 128 bits (16 bytes).
const aesBlockSize = 16

// BytesToUint64 converts a buffer to a slice of unsigned 64-bit integers.
func BytesToUint64(buf []byte) []uint64 {
	res := make([]uint64, len(buf)/8)
	for i := 0; i < len(res); i++ {
		res[i] = binary.LittleEndian.Uint64(buf[8*i:])
	}
	return res
}

// Uint64ToBytes converts a slice of unsigned 64-bit integers to a buffer.
func Uint64ToBytes(nums []uint64) []byte {
	res := make([]byte, len(nums)*8)
	for i := 0; i < len(nums); i++ {
		binary.LittleEndian.PutUint64(res[8*i:], nums[i])
	}
	return res
}

// ctr contains a block cipher and initialization vector.
type ctr struct {
	b   cipher.Block
	ctr []uint64
	pos int
}

// NewCTR returns a CTR mode stream cipher.
func NewCTR(block cipher.Block, iv []byte) cipher.Stream {
	if block.BlockSize() != len(iv) {
		panic("NewCTR: initialization vector length must equal block size")
	}
	return ctr{block, BytesToUint64(iv), 0}
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
		tmp := make([]byte, stream.b.BlockSize())
		stream.b.Encrypt(tmp, Uint64ToBytes(stream.ctr))

		// Panic if dst is smaller than src.
		for len(src) > 0 && stream.pos < stream.b.BlockSize() {
			dst[0] = src[0] ^ tmp[stream.pos]
			dst = dst[1:]
			src = src[1:]
			stream.pos++
		}
		if stream.pos == stream.b.BlockSize() {
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
		fmt.Fprintln(os.Stderr, err.Error())
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
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	stream.XORKeyStream(buf, buf)
	fmt.Println(string(buf))
}

var e = flag.Bool("e", false, "encrypt")

func main() {
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
	iv := make([]byte, aesBlockSize)
	stream := NewCTR(block, iv)

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
			fmt.Fprintln(os.Stderr, err.Error())
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
