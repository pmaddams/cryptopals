#include <sys/types.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "mt.h"

void
mt_init(struct mt *mt, uint32_t seed)
{
	size_t i;

	for (mt->state[0] = seed, i = 1; i < NSTATE; i++)
		mt->state[i] = 1812433253 * (mt->state[i-1] ^ (mt->state[i-1] >> 30)) + i;

	mt->i = i;
}

static void
mt_twist(struct mt *mt)
{
	size_t i;
	uint32_t x;

	for (i = 0; i < NSTATE; i++) {
		x = (mt->state[i] & 0x80000000) | (mt->state[i+1] & 0x7fffffff);
		mt->state[i] = mt->state[(i+397) % NSTATE] ^ (x >> 1);
		if (x & 1)
			mt->state[i] ^= 0x9908b0df;
	}

	mt->i = 0;
}

uint32_t
mt_rand(struct mt *mt)
{
	uint32_t x;

	if (mt->i == NSTATE)
		mt_twist(mt);

	x = mt->state[mt->i++];

	x ^= (x >> 11);
	x ^= (x << 7) & 0x9d2c5680;
	x ^= (x << 15) & 0xefc60000;
	x ^= (x >> 18);

	return x;
}

uint8_t *
mt_crypt(uint8_t *in, size_t inlen, uint32_t seed)
{
	size_t outlen, i, j;
	uint8_t *out;
	struct mt mt;
	uint32_t x;

	if (in == NULL || inlen == 0) {
		errno = EINVAL;
		goto fail;
	}

	outlen = ((inlen-1)/BLKSIZ+1)*BLKSIZ;
	if ((out = malloc(outlen)) == NULL)
		goto fail;

	mt_init(&mt, seed);

	for (i = 0; i < outlen; i += BLKSIZ) {
		x = mt_rand(&mt);
		memcpy(out+i, &x, BLKSIZ);
	}
	for (i = 0; i < inlen; i++)
		out[i] ^= in[i];

	out[inlen] = '\0';
	return out;
fail:
	return NULL;
}
