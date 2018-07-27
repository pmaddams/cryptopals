package main

import (
	"bytes"
	"crypto/hmac"
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

// NewHandler takes an HMAC hash and returns an HTTP handler.
func NewHandler(hm hash.Hash) http.Handler {
	return handler{hm, new(sync.Mutex)}
}

// ServeHTTP responds to upload requests with 200 OK if the file HMAC
// matches its signature, and 500 Internal Server Error otherwise.
func (x handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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
	x.Lock()

	x.Reset()
	io.Copy(x, f)
	sum := x.Sum([]byte{})

	x.Unlock()
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
			if n, err := timedUpload(url, buf, name, sig); err != nil {
				log.Fatal(err)
			} else if n > best {
				best = n
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

// breakHMAC prints a valid HMAC and attempts to break the server.
func breakHMAC(hm hash.Hash, url string, buf []byte, name string) error {
	hm.Reset()
	hm.Write(buf)
	fmt.Printf("attempting to upload %s...\n%x\n", name, hm.Sum([]byte{}))

	sig := hex.EncodeToString(breakServer(url, buf, name, hm.Size()))
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
	h := hmac.New(sha1.New, key)

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
		err := breakHMAC(h, url, buf.Bytes(), "user input")
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
		err = breakHMAC(h, url, buf.Bytes(), name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		buf.Reset()
		f.Close()
	}
}
