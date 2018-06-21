package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
)

const (
	arraySize   = 624
	offset      = 397
	multiplier  = 1812433253
	upperMask   = 0x80000000
	lowerMask   = 0x7fffffff
	coefficient = 0x9908b0df
	temperMask1 = 0x9d2c5680
	temperMask2 = 0xefc60000
)

// MT represents an MT19937 (32-bit Mersenne Twister) PRNG.
type MT struct {
	state [arraySize]uint32
	pos   int
}

// NewMT initializes and returns a new MT19937 PRNG.
func NewMT(seed uint32) *MT {
	var mt MT
	mt.state[0] = seed
	for i := 1; i < len(mt.state); i++ {
		mt.state[i] = multiplier*
			(mt.state[i-1]^(mt.state[i-1]>>30)) +
			uint32(i)
	}
	mt.twist()
	return &mt
}

// twist scrambles the MT19937 state array.
func (mt *MT) twist() {
	for i := range mt.state {
		n := (mt.state[i] & upperMask) | (mt.state[(i+1)%len(mt.state)] & lowerMask)
		mt.state[i] = mt.state[(i+offset)%len(mt.state)] ^ (n >> 1)
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
	if mt.pos == len(mt.state) {
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
