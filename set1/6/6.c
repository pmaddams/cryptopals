#include <sys/types.h>
#include <sys/param.h>

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "freq.h"

#define MINLEN 6
#define MAXLEN 40
#define NBLOCK 4

int
dist(uint8_t *b1, uint8_t *b2, size_t len)
{
	int res;
	uint8_t c;

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

	if (guess*(NBLOCK+1) >= len)
		goto fail;

	for (sum = i = 0; i < NBLOCK; i++) {
		memcpy(tmp, buf+(i+1)*guess, guess);
		buf += i*guess;
		sum += dist(buf, tmp, guess);
	}

	return (float) sum / (guess*NBLOCK);
fail:
	return 8.;
}

size_t
crack_keylen(uint8_t *buf, size_t len)
{
	size_t guess, found, max;
	float score, best;

	max = MIN(len/(NBLOCK+1), MAXLEN);

	for (best = 8., found = guess = MINLEN; guess <= max; guess++)
		if ((score = keydist(buf, len, guess)) < best) {
			best = score;
			found = guess;
		}

	return found;
}

void
xor(uint8_t *buf, size_t len, uint8_t c)
{
	while (len--)
		*buf++ ^= c;
}

float
score_buf(uint8_t *buf, size_t len)
{
	float res;
	uint8_t c;

	for (res = 0.; len--;)
		switch (c = *buf++) {
		case ' ':
			res += freq[0];
			break;
		case 'A'...'Z':
			c = c - 'A' + 'a';
			/* FALLTHROUGH */
		case 'a'...'z':
			res += freq[1 + c - 'a'];
			break;
		default:
			break;
		}

	return res;
}

char *
crack_key(uint8_t *buf, size_t len, size_t keylen)
{
	size_t i, j, tmplen;
	char *tmp, *cp, *key;
	float score, best;
	int c;

	len -= len % keylen;
	tmplen = len / keylen;

	if ((tmp = malloc(tmplen)) == NULL ||
	    (cp = malloc(tmplen)) == NULL ||
	    (key = malloc(keylen+1)) == NULL)
		goto fail;

	for (i = 0; i < keylen; i++) {
		for (j = 0; j < tmplen; j++)
			tmp[j] = buf[j*keylen+i];

		for (best = 0., c = 0; c <= UINT8_MAX; c++) {
			memcpy(cp, tmp, tmplen);
			xor(cp, tmplen, c);
			if ((score = score_buf(cp, tmplen)) > best) {
				best = score;
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
	size_t i, len, keylen;
	ssize_t nr;

	if ((bio = BIO_new_fp(stdin, BIO_NOCLOSE)) == NULL ||
	    (b64 = BIO_new(BIO_f_base64())) == NULL ||
	    (memstream = open_memstream(&buf, &len)) == NULL)
		err(1, NULL);

	BIO_push(b64, bio);

	while ((nr = BIO_read(b64, tmp, BUFSIZ)) > 0)
		if (fwrite(tmp, nr, 1, memstream) < 1)
			err(1, NULL);
	fclose(memstream);

	BIO_free_all(b64);

	keylen = crack_keylen(buf, len);
	if ((key = crack_key(buf, len, keylen)) == NULL)
		err(1, NULL);

	printf("key: %s\n\n", key);

	for (i = 0; i < len; i++)
		putchar(buf[i] ^ key[i%keylen]);
	putchar('\n');

	exit(0);
}
