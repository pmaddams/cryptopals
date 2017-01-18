#include <sys/types.h>

#include <stdio.h>
#include <time.h>

#include "mt.h"

#define MASK(a, b) ((~0>>(a)) & (~0<<31-(b)))

uint32_t
untemper(uint32_t x)
{
	x ^= (x>>18) & MASK(18,31);

	x ^= (x<<15) & MASK(2,16) & 0xefc60000;
	x ^= (x<<15) & MASK(0,1) & 0xefc60000;

	x ^= (x<<7) & MASK(18,24) & 0x9d2c5680;
	x ^= (x<<7) & MASK(11,17) & 0x9d2c5680;
	x ^= (x<<7) & MASK(4,10) & 0x9d2c5680;
	x ^= (x<<7) & MASK(0,3) & 0x9d2c5680;

	x ^= (x>>11) & MASK(11,21);
	x ^= (x>>11) & MASK(22,31);

	return x;
}

int
main(void)
{
	struct mt mt0, mt1;
	time_t t;
	size_t i, len;
	uint32_t state[NSTATE];

	mt_init(&mt0, time(&t));

	for (i = 0; i < NSTATE; i++)
		state[i] = untemper(mt_rand(&mt0));

	mt_clone(&mt1, state);

	while (fgetln(stdin, &len)) {
		printf("mt0: %u\n", mt_rand(&mt0));
		printf("mt1: %u\n", mt_rand(&mt1));
	}

	return 0;
}
