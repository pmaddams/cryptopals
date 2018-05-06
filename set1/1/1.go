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
	var b []byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// convert reads hexadecimal input and writes base64.
func convert(dst io.Writer, src io.Reader) {
	input := bufio.NewScanner(src)
	for input.Scan() {
		s, err := HexToB64(input.Text())
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return
		}
		fmt.Fprintln(dst, s)
	}
	if err := input.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
}

func main() {
	files := os.Args[1:]
	// If no files are specified, read from standard input.
	if len(files) == 0 {
		convert(os.Stdout, os.Stdin)
		return
	}
	for _, arg := range files {
		f, err := os.Open(arg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		convert(os.Stdout, f)
		f.Close()
	}
}
