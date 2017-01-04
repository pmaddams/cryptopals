#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "tab.h"

#define MINKEY		2
#define MAXKEY		40
#define NBLK		4

#define MINIMUM(a, b)	((a)<(b)?(a):(b))

int
dist(uint8_t b1, uint8_t b2, size_t len)
{
	uint8_t c;
	int res;

	for (res = 0; len--;) {
		c = *b1++ ^ *b2++;
		while (c > 0) {
			c &= c - 1;
			res++;
		}
	}

	return res;
}

float
keydist(uint8_t *buf, size_t len, size_t guess)
{
	int i, sum;
	uint8_t tmp[guess];

	if (guess*NBLK >= len)
		goto fail;

	for (sum = i = 0; i < NBLK; i++) {
		memcpy(tmp, buf+i*guess, guess);
		buf += i*guess;
		sum += dist(buf, tmp, guess);
	}

	return (float) sum / (guess*NBLK);
fail:
	return 8.;
}

size_t
crack_keylen(uint8_t *buf, size_t len)
{
	float scr, best;
	size_t guess, found, max;

	max = MINIMUM(len/NBLK, MAXKEY);

	for (best = 8., found = guess = MINKEY; guess <= max; guess++)
		if ((scr = keydist(buf, len, guess)) < best) {
			best = scr;
			found = guess;
		}

	return found;
}

float
score(uint8_t *buf, size_t len)
{
	float res;
	uint8_t c;

	for (res = 0.; len--;)
		if (isprint(c = *buf++))
			switch (c) {
			case ' ':
				res += tab[0];
				break;
			case 'A'...'Z':
				c = c - 'A' + 'a';
				/* FALLTHROUGH */
			case 'a'...'z':
				res += tab[1 + c - 'a'];
				break;
			default:
				break;
			}

	return res;
}

char *
crack_key(uint8_t *buf, size_t len)
{
	
}
