package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
)

const arraySize = 624
const offset = 397
const multiplier = 1812433253
const upperMask = 0x80000000
const lowerMask = 0x7fffffff
const coefficient = 0x9908b0df
const temperMask1 = 0x9d2c5680
const temperMask2 = 0xefc60000

// MT contains state for the MT19937 (32-bit Mersenne Twister) PRNG.
type MT struct {
	state [arraySize]uint32
	pos   int
}

// NewMT initializes and returns a new MT19937 PRNG.
func NewMT(seed uint32) *MT {
	var mt MT
	mt.state[0] = seed
	for i := 1; i < arraySize; i++ {
		mt.state[i] = multiplier*
			(mt.state[i-1]^(mt.state[i-1]>>30)) +
			uint32(i)
	}
	mt.twist()
	return &mt
}

// twist scrambles the MT19937 state array.
func (mt *MT) twist() {
	for i := 0; i < arraySize; i++ {
		n := (mt.state[i] & upperMask) | (mt.state[(i+1)%arraySize] & lowerMask)
		mt.state[i] = mt.state[(i+offset)%arraySize] ^ (n >> 1)
		if n&1 == 1 {
			mt.state[i] ^= coefficient
		}
	}
}

// temper applies the MT19937 tempering transformation.
func temper(n uint32) uint32 {
	n ^= n >> 11
	n ^= (n << 7) & temperMask1
	n ^= (n << 15) & temperMask2
	n ^= n >> 18

	return n
}

// Uint32 returns a pseudo-random unsigned 32-bit integer.
func (mt *MT) Uint32() uint32 {
	n := temper(mt.state[mt.pos])
	mt.pos++
	if mt.pos == arraySize {
		mt.twist()
		mt.pos = 0
	}
	return n
}

func main() {
	var seed uint
	flag.UintVar(&seed, "s", 5489, "seed")
	flag.Parse()

	mt := NewMT(uint32(seed))
	input := bufio.NewScanner(os.Stdin)
	for input.Scan() {
		fmt.Print(mt.Uint32())
	}
}
