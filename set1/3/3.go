package main

import (
	"io"
	"io/ioutil"
)

// Classify decides if a byte is a letter, a space, or neither.
func Classify(b byte) byte {
	switch {
	case b >= 'A' && b <= 'Z':
		return b
	case b >= 'a' && b <= 'z':
		return b - 'a' + 'A'
	case b == ' ' || b == '\n':
		return ' '
	default:
		return 0
	}
}

// LetterFrequency reads text and returns a map of letter frequencies.
func LetterFrequency(r io.Reader) (map[byte]float64, error) {
	bytes, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	m := make(map[byte]float64)

	// A point represents a unit fraction of the data.
	point := float64(1/len(bytes))
	for _, b := range bytes {
		m[Classify(b)] += point
	}
	return m, nil
}

// Score adds up the points for letters and spaces in the provided buffer.
func Score(m map[byte]float64, bytes []byte) (res float64) {
	for _, b := range bytes {
		if k := Classify(b); k != 0 {
			f, _ := m[k]
			res += f
		}
	}
	return
}

func main() {
}
