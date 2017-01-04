#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define MAXKEY	40
#define NBLK	4

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
keydist(uint8_t *buf, size_t len, size_t keylen)
{
	uint8_t *tmp;
	int i, sum;

	if (keylen*NBLK >= len ||
	    (tmp = malloc(keylen)) == NULL)
		goto fail;

	for (sum = i = 0; i < NBLK; i++) {
		memcpy(tmp, buf+i*keylen, keylen);
		buf += i*keylen;
		sum += dist(buf, tmp, keylen);
	}

	return (float) sum / (keylen*NBLK);
fail:
	return 0.
}
