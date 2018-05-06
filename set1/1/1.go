package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func convert(dst io.Writer, src io.Reader) (int64, error) {
	b64 := base64.NewEncoder(base64.StdEncoding, dst)
	defer b64.Close()

	return io.Copy(b64, hex.NewDecoder(src))
}

func main() {
	if len(os.Args) == 1 {
		convert(os.Stdout, os.Stdin)
		fmt.Println()
		return
	}
	for _, arg := range os.Args[1:] {
		f, err := os.Open(arg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			continue
		}
		convert(os.Stdout, f)
		fmt.Println()
	}
}
