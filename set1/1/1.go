package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// HexToBase64 converts a hex-encoded string to base64.
func HexToBase64(s string) (string, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// convertHex reads hex-encoded input and prints base64.
func convertHex(in io.Reader) error {
	input := bufio.NewScanner(in)
	for input.Scan() {
		s, err := HexToBase64(input.Text())
		if err != nil {
			return err
		}
		fmt.Println(s)
	}
	return input.Err()
}

func main() {
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		if err := convertHex(os.Stdin); err != nil {
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
		if err := convertHex(f); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
