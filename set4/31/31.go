package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log"
	weak "math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

func init() { weak.Seed(time.Now().UnixNano()) }

const delay = 5 * time.Millisecond

const (
	addr = "localhost:9000"
	path = "/test"
)

// min returns the smaller of two integers.
func min(n, m int) int {
	if n < m {
		return n
	}
	return m
}

// XORBytes produces the XOR combination of two buffers.
func XORBytes(dst, b1, b2 []byte) int {
	n := min(len(b1), len(b2))
	for i := 0; i < n; i++ {
		dst[i] = b1[i] ^ b2[i]
	}
	return n
}

// hmac represents a hash for a hash-based message authentication code.
type hmac struct {
	hash.Hash
	ipad []byte
	opad []byte
	buf  *bytes.Buffer
}

// NewHMAC takes a hash and key, and returns a new HMAC hash.
func NewHMAC(fn func() hash.Hash, key []byte) hash.Hash {
	h := fn()
	// If the key is too long, hash it.
	if len(key) > h.BlockSize() {
		h.Write(key)
		key = h.Sum([]byte{})
		h.Reset()
	}
	ipad := bytes.Repeat([]byte{0x36}, h.BlockSize())
	opad := bytes.Repeat([]byte{0x5c}, h.BlockSize())

	XORBytes(opad, opad, key)
	XORBytes(ipad, ipad, key)

	return &hmac{h, ipad, opad, new(bytes.Buffer)}
}

// Reset resets the hash.
func (h *hmac) Reset() {
	h.buf.Reset()
}

// Write writes data to the hash.
func (h *hmac) Write(buf []byte) (int, error) {
	return h.buf.Write(buf)
}

// Sum appends a checksum to the given buffer.
func (h *hmac) Sum(buf []byte) []byte {
	h.Hash.Write(h.ipad)
	h.Hash.Write(h.buf.Bytes())

	sum := h.Hash.Sum([]byte{})
	h.Hash.Reset()

	h.Hash.Write(h.opad)
	h.Hash.Write(sum)

	sum = h.Hash.Sum([]byte{})
	h.Hash.Reset()

	return append(buf, sum...)
}

// RandomRange returns a pseudo-random non-negative integer in [lo, hi].
// The output should not be used in a security-sensitive context.
func RandomRange(lo, hi int) int {
	if lo < 0 || lo > hi {
		panic("RandomRange: invalid range")
	}
	return lo + weak.Intn(hi-lo+1)
}

// RandomBytes returns a random buffer of the desired length.
func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

// insecureCompare compares two buffers one byte at a time,
// returning false upon finding a mismatched pair of bytes.
func insecureCompare(b1, b2 []byte) bool {
	for len(b1) != 0 && len(b2) != 0 {
		if b1[0] != b2[0] {
			return false
		}
		b1, b2 = b1[1:], b2[1:]
		time.Sleep(delay)
	}
	return len(b1) == len(b2)
}

// handler represents an HTTP handler.
type handler struct {
	hash.Hash
	*sync.Mutex
}

// NewHandler takes a hash and returns an HTTP handler.
func NewHandler(h hash.Hash) http.Handler {
	return handler{h, new(sync.Mutex)}
}

// ServeHTTP responds to upload requests with 200 OK if the file HMAC
// matches its signature, and 500 Internal Server Error otherwise.
func (h handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	f, _, err := req.FormFile("file")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sig, err := hex.DecodeString(req.FormValue("signature"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Acquire a lock to prevent concurrent hashing.
	h.Lock()

	h.Reset()
	io.Copy(h, f)
	sum := h.Sum([]byte{})

	h.Unlock()
	if !insecureCompare(sig, sum) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// 200 OK
}

// upload uploads a file and hex-encoded signature, and returns the response.
func upload(url string, buf []byte, name, sig string) (*http.Response, error) {
	tmp := new(bytes.Buffer)
	m := multipart.NewWriter(tmp)

	part, err := m.CreateFormFile("file", name)
	if err != nil {
		return nil, err
	}
	part.Write(buf)
	if err = m.WriteField("signature", sig); err != nil {
		return nil, err
	}
	contentType := m.FormDataContentType()
	m.Close()

	return http.Post(url, contentType, tmp)
}

// timedUpload sends a request and returns the time it takes to receive a response.
func timedUpload(url string, buf []byte, name, sig string) (int64, error) {
	start := time.Now()
	if _, err := upload(url, buf, name, sig); err != nil {
		return 0, err
	}
	return time.Since(start).Nanoseconds(), nil
}

// breakServer returns a valid HMAC for uploading an arbitrary file.
func breakServer(url string, buf []byte, name string, size int) []byte {
	res := make([]byte, size)
	loop := func(i int) byte {
		var (
			b    byte
			best int64
		)
		for j := 0; j <= 0xff; j++ {
			res[i] = byte(j)
			sig := hex.EncodeToString(res)
			if t, err := timedUpload(url, buf, name, sig); err != nil {
				log.Fatal(err)
			} else if t > best {
				best = t
				b = byte(j)
			}
		}
		return b
	}
	// Double-check each byte to compensate for timing errors.
	for i := range res {
		prev, b := loop(i), loop(i)
		for b != prev {
			prev = b
			b = loop(i)
		}
		res[i] = b
		fmt.Printf("%02x", b)
	}
	fmt.Println()
	return res
}

// printHMACAndBreakServer prints a valid HMAC and attempts to break the server.
func printHMACAndBreakServer(h hash.Hash, url string, buf []byte, name string) error {
	h.Reset()
	h.Write(buf)
	fmt.Printf("attempting to upload %s...\n%x\n", name, h.Sum([]byte{}))

	sig := hex.EncodeToString(breakServer(url, buf, name, h.Size()))
	resp, err := upload(url, buf, name, sig)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK {
		fmt.Printf("successfully uploaded %s\n", name)
	}
	return nil
}

func main() {
	key := RandomBytes(RandomRange(8, 64))
	h := NewHMAC(sha1.New, key)

	go func() {
		log.Fatal(http.ListenAndServe(addr, NewHandler(h)))
	}()
	// Wait for the server.
	if c, err := net.DialTimeout("tcp", addr, time.Second); err != nil {
		log.Fatal(err)
	} else {
		c.Close()
	}
	url := fmt.Sprintf("http://%s%s", addr, path)
	buf := new(bytes.Buffer)

	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		io.Copy(buf, os.Stdin)
		err := printHMACAndBreakServer(h, url, buf.Bytes(), "user input")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		io.Copy(buf, f)
		err = printHMACAndBreakServer(h, url, buf.Bytes(), name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		buf.Reset()
		f.Close()
	}
}
