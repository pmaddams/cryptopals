#include <sys/types.h>

#include <stdio.h>

#define SEED	5489

#define NSTATES	624

struct mt {
	uint32_t state[NSTATES];
	size_t i;
};

void
mt_init(struct mt *mt, uint32_t seed)
{
	size_t i;

	for (mt->state[0] = seed, i = 1; i < NSTATES; i++)
		mt->state[i] = 1812433253 * (mt->state[i-1] ^ (mt->state[i-1] >> 30)) + i;

	mt->i = i;
}

void
mt_twist(struct mt *mt)
{
	size_t i;
	uint32_t x;

	for (i = 0; i < NSTATES; i++) {
		x = (mt->state[i] & 0x80000000) | (mt->state[i+1] & 0x7fffffff);
		mt->state[i] = mt->state[(i+397) % NSTATES] ^ (x >> 1);
		if (x & 1)
			mt->state[i] ^= 0x9908b0df;
	}

	mt->i = 0;
}

uint32_t
mt_rand(struct mt *mt)
{
	uint32_t x;

	if (mt->i == NSTATES)
		mt_twist(mt);

	x = mt->state[mt->i++];

	x ^= (x >> 11);
	x ^= (x << 7) & 0x9d2c5680;
	x ^= (x << 15) & 0xefc60000;
	x ^= (x >> 18);

	return x;
}

int
main(void)
{
	struct mt mt;
	size_t len;

	mt_init(&mt, SEED);

	while (fgetln(stdin, &len))
		printf("%u\n", mt_rand(&mt));

	return 0;
}
