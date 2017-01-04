#include <err.h>
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
dist(uint8_t *b1, uint8_t *b2, size_t len)
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

char *
crack_key(uint8_t *buf, size_t len, size_t keylen)
{
	size_t i;
	char *bufarray[keylen], *key;

	len -= (len % keylen);

	for (i = 0; i < keylen; i++)
		if ((bufarray[i] = malloc(len/keylen)) == NULL)
			goto fail;

	for (i = 0; i < len; i++)
		bufarray[i%keylen][i/keylen] = buf[i];

fail:
	return NULL;
}

int
main(void)
{
	BIO *bio, *b64;
	FILE *memstream;
	char *buf, tmp[BUFSIZ];
	size_t len;
	int nr;

	if ((bio = BIO_new_fp(stdin, BIO_NOCLOSE)) == NULL ||
	    (b64 = BIO_new(BIO_f_base64())) == NULL ||
	    (memstream = open_memstream(&buf, &len)) == NULL)
		err(1, NULL);

	BIO_push(b64, bio);

	while ((nr = BIO_read(b64, tmp, BUFSIZ)) > 0)
		fwrite(tmp, nr, 1, memstream);
	fclose(memstream);

	exit(0);
}
