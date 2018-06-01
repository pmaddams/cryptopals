package main

import (
	"bufio"
	"fmt"
	"os"
	"time"
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

// BitMask returns an unsigned 32-bit integer with bits [i, j] set.
func BitMask(i, j int) uint32 {
	if i < 0 || i > j || j > 31 {
		panic("BitMask: invalid range")
	}
	rs, ls := uint(i), uint(31-j)
	return (^uint32(0) >> (rs + ls)) << ls
}

// Untemper reverses the MT19937 tempering transformation.
func Untemper(n uint32) uint32 {
	n ^= (n >> 18) & BitMask(18, 31)
	n ^= (n << 15) & BitMask(2, 16) & temperMask2
	n ^= (n << 15) & BitMask(0, 1) & temperMask2
	n ^= (n << 7) & BitMask(18, 24) & temperMask1
	n ^= (n << 7) & BitMask(11, 17) & temperMask1
	n ^= (n << 7) & BitMask(4, 10) & temperMask1
	n ^= (n << 7) & BitMask(0, 3) & temperMask1
	n ^= (n >> 11) & BitMask(11, 21)
	n ^= (n >> 11) & BitMask(22, 31)

	return n
}

// CloneMT clones an MT19937 PRNG from 624 consecutive outputs.
func CloneMT(mt *MT) *MT {
	var clone MT
	for i := 0; i < arraySize; i++ {
		clone.state[i] = Untemper(mt.Uint32())
	}
	clone.twist()
	return &clone
}

// printColumns prints values in two columns.
func printColumns(a, b interface{}) {
	fmt.Printf("%-10v\t%-10v", a, b)
}

func main() {
	mt := NewMT(uint32(time.Now().Unix()))
	clone := CloneMT(mt)

	input := bufio.NewScanner(os.Stdin)
	printColumns("Original:", "Clone:")
	for input.Scan() {
		printColumns(mt.Uint32(), clone.Uint32())
	}
}
