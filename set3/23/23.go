package main

import (
	"bufio"
	"fmt"
	"os"
	"time"
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
	for i := range clone.state {
		clone.state[i] = Untemper(mt.Uint32())
	}
	clone.twist()
	return &clone
}

// printColumns prints values in two columns.
func printColumns(a, b interface{}) {
	fmt.Printf("%-10v\t%v", a, b)
}

func main() {
	mt1 := NewMT(uint32(time.Now().Unix()))
	mt2 := CloneMT(mt1)

	input := bufio.NewScanner(os.Stdin)
	printColumns("Original:", "Clone:")
	for input.Scan() {
		printColumns(mt1.Uint32(), mt2.Uint32())
	}
}
