#include <err.h>
#include <stdint.h>
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

void
xor(uint8_t *buf, uint8_t c, size_t len)
{
	while (len--)
		*buf++ ^= c;
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
crack_key(uint8_t *buf, size_t len, size_t keylen)
{
	char *tmp, *cp, *key;
	size_t i, j, tmplen;
	float scr, best;
	uint8_t c;

	len -= (len % keylen);
	tmplen = len / keylen;

	if ((tmp = malloc(tmplen)) == NULL ||
	    (cp = malloc(tmplen)) == NULL ||
	    (key = malloc(keylen+1)) == NULL)
		err(1, NULL);

	for (i = 0; i < keylen; i++) {
		for (j = 0; j < tmplen; j++)
			tmp[j] = buf[(j*keylen)+i];

		for (best = 0., c = 0; c < UINT8_MAX; c++) {
			memcpy(cp, tmp, tmplen);
			xor(cp, c, tmplen);
			if ((scr = score(cp, tmplen)) > best) {
				best = scr;
				key[i] = c;
			}
		}
	}
	key[i] = '\0';

	free(tmp);
	free(cp);
	return key;
fail:
	return NULL;
}

int
main(void)
{
	BIO *bio, *b64;
	FILE *memstream;
	char *buf, tmp[BUFSIZ], *key;
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

	key = crack_key(buf, len, 29);
	puts(key);

	exit(0);
}
