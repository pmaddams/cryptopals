package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"strings"
)

// message represents a message signed with DSA.
type message struct {
	s *big.Int
	r *big.Int
	m *big.Int
}

// scanAfterPrefix reads a line and returns the string after a prefix.
func scanAfterPrefix(input *bufio.Scanner, prefix string) (string, error) {
	if input.Scan(); input.Err() != nil {
		return "", input.Err()
	}
	if !strings.HasPrefix(input.Text(), prefix) {
		return "", errors.New("scanAfterPrefix: invalid input")
	}
	return input.Text()[len(prefix):], nil
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
	if sum, err := hex.DecodeString(s); err != nil {
		return nil, err
	} else if !bytes.Equal(sum, array[:]) {
		return nil, errors.New("scanMessage: invalid checksum")
	} else {
		msg.m = new(big.Int).SetBytes(sum)
	}
	return msg, nil
}

// readMessages reads all messages from the input.
func readMessages(in io.Reader) ([]*message, error) {
	input := bufio.NewScanner(in)
	var msgs []*message
	for {
		if msg, err := scanMessage(input); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		} else {
			msgs = append(msgs, msg)
		}
	}
	return msgs, input.Err()
}

// generatePairs returns a channel that yields all pairs of messages.
func generatePairs(msgs []*message) <-chan []*message {
	ch := make(chan []*message)
	go func() {
		for i := 0; i < len(msgs)-1; i++ {
			for j := i + 1; j < len(msgs); j++ {
				ch <- append([]*message{msgs[i]}, msgs[j])
			}
		}
		close(ch)
	}()
	return ch
}

func main() {
}
