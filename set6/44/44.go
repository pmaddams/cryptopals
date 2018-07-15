package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

// message represents a message signed with DSA.
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

// scanAfterPrefix reads a line and returns the string after a prefix.
func scanAfterPrefix(input *bufio.Scanner, prefix string) (string, error) {
	input.Scan()
	if err := input.Err(); err != nil {
		return "", err
	}
	if !strings.HasPrefix(input.Text(), prefix) {
		return "", errors.New("scanAfterPrefix: invalid input")
	}
	return input.Text()[len(prefix):], nil
}

// scanMessage reads lines matching the message format and returns the message.
func scanMessage(input *bufio.Scanner) (*message, error) {
	msg := new(message)
	var (
		s   string
		err error
	)
	if s, err = scanAfterPrefix(input, "msg: "); err != nil {
		return nil, err
	}
	array := sha1.Sum([]byte(s))
	if s, err = scanAfterPrefix(input, "s: "); err != nil {
		return nil, err
	}
	if msg.s, err = parseBigInt(s, 10); err != nil {
		return nil, err
	}
	if s, err = scanAfterPrefix(input, "r: "); err != nil {
		return nil, err
	}
	if msg.r, err = parseBigInt(s, 10); err != nil {
		return nil, err
	}
	if s, err = scanAfterPrefix(input, "m: "); err != nil {
		return nil, err
	}
	if msg.sum, err = hex.DecodeString(s); err != nil {
		return nil, err
	} else if !bytes.Equal(msg.sum, array[:]) {
		return nil, errors.New("scanMessage: invalid checksum")
	}
	return msg, nil
}

func main() {
}
