package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// HexToB64 converts a hexadecimal string to base64.
func HexToB64(s string) (string, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// convertAndPrint reads hex-encoded input and prints base64.
func convertAndPrint(in io.Reader) error {
	input := bufio.NewScanner(in)
	for input.Scan() {
		s, err := HexToB64(input.Text())
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
		if err := convertAndPrint(os.Stdin); err != nil {
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
		if err := convertAndPrint(f); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		f.Close()
	}
}
