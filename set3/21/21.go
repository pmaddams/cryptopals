package main

import (
	"bufio"
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

type rand struct {
	state [arraySize]uint32
	pos   int
}

func NewRand(seed uint32) *rand {
	var rand rand
	rand.state[0] = seed
	for i := 1; i < arraySize; i++ {
		rand.state[i] = multiplier*
			(rand.state[i-1]^(rand.state[i-1]>>30)) +
			uint32(i)
	}
	return &rand
}

func (rand *rand) twist() {
	for i := 0; i < arraySize; i++ {
		n := (rand.state[i] & upperMask) | (rand.state[(i+1)%arraySize] & lowerMask)
		rand.state[i] = rand.state[(i+offset)%arraySize] ^ (n >> 1)
		if n%2 != 0 {
			rand.state[i] ^= coefficient
		}
	}
}

func (rand *rand) Uint32() uint32 {
	n := rand.state[rand.pos]
	n ^= (n >> 11)
	n ^= (n << 7) & temperMask1
	n ^= (n << 15) & temperMask2
	n ^= (n >> 18)

	rand.pos++
	if rand.pos == arraySize {
		rand.twist()
		rand.pos = 0
	}
	return n
}

func main() {
	rand := NewRand(5489)
	input := bufio.NewScanner(os.Stdin)
	for input.Scan() {
		fmt.Print(rand.Uint32())
	}
}
