package main

import (
	"bufio"
	_ "crypto/aes"
	_ "crypto/cipher"
	_ "crypto/rand"
	"encoding/base64"
	weak "math/rand"
	"os"
	"time"
)

// randomSecret picks a base64-encoded line at random and decodes it.
func randomSecret(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	lines := []string{}
	input := bufio.NewScanner(f)
	for input.Scan() {
		lines = append(lines, input.Text())
	}
	if err := input.Err(); err != nil {
		return nil, err
	}
	weak := weak.New(weak.NewSource(time.Now().UnixNano()))
	s := lines[weak.Intn(len(lines))]

	return base64.StdEncoding.DecodeString(s)
}

func main() {
}
