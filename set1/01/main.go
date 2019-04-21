// 1. Convert hex to base64

package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func main() {
	files := os.Args[1:]
	if len(files) == 0 {
		if err := convert(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := convert(f); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}

// convert reads hex-encoded input and prints base64.
func convert(in io.Reader) error {
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

// HexToBase64 converts a hex-encoded string to base64.
func HexToBase64(s string) (string, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}
