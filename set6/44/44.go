package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

type message struct {
	s   *big.Int
	r   *big.Int
	sum []byte
}

// parseBigInt converts a string to an arbitrary-precision integer.
func parseBigInt(s string, base int) (*big.Int, error) {
	if base < 0 || base > 16 {
		return nil, errors.New("parseBigInt: invalid base")
	}
	s = strings.Replace(s, "\n", "", -1)
	z, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, errors.New("parseBigInt: invalid string")
	}
	return z, nil
}

func readMessage(in io.Reader) (*message, error) {
	msg := new(message)
	var (
		s   string
		err error
	)
	if _, err = fmt.Fscanln(in, &s); err != nil {
		return nil, err
	}
	array := sha1.Sum([]byte(s))
	if _, err = fmt.Fscanln(in, &s); err != nil {
		return nil, err
	}
	if msg.s, err = parseBigInt(s, 10); err != nil {
		return nil, err
	}
	if _, err = fmt.Fscanln(in, &s); err != nil {
		return nil, err
	}
	if msg.r, err = parseBigInt(s, 10); err != nil {
		return nil, err
	}
	if _, err = fmt.Fscanln(in, &s); err != nil {
		return nil, err
	}
	if msg.sum, err = hex.DecodeString(s); err != nil {
		return nil, err
	} else if !bytes.Equal(msg.sum, array[:]) {
		return nil, errors.New("readMessage: invalid checksum")
	}
	return msg, nil
}

func main() {
}
