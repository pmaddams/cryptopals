#include <sys/types.h>

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "mt.h"

#define KEY 12345

char *
get_token(void)
{
	size_t inlen, outlen;
	char *in, *enc, *out;
	time_t t;
	BIO *b64, *bio_out;
	FILE *memstream;
	ssize_t nr;

	inlen = arc4random_uniform(14) + 14;
	if ((in = malloc(inlen)) == NULL)
		goto fail;

	arc4random_buf(in, inlen-14);
	memset(in+inlen-14, 'A', 14);

	time(&t);

	if ((enc = mt_crypt(in, inlen, t)) == NULL ||
	    (b64 = BIO_new(BIO_f_base64())) == NULL ||
	    (memstream = open_memstream(&out, &outlen)) == NULL ||
	    (bio_out = (BIO_new_fp(memstream, BIO_NOCLOSE))) == NULL)
		goto fail;

	BIO_push(b64, bio_out);

	if (BIO_write(b64, enc, inlen) <= 0 ||
	    BIO_flush(b64) <= 0)
		goto fail;
	fclose(memstream);

	free(in);
	free(enc);
	BIO_free_all(b64);

	return out;
fail:
	return NULL;
}

bool
is_valid(char *token)
{
	bool res;
	time_t t;
	BIO *b64_mem, *b64;
	FILE *memstream;
	char *enc, tmp[BUFSIZ], *dec;
	size_t len;
	ssize_t nr;

	time(&t);

	res = false;

	if ((b64_mem = BIO_new_mem_buf(token, strlen(token))) == NULL ||
	    (b64 = BIO_new(BIO_f_base64())) == NULL ||
	    (memstream = open_memstream(&enc, &len)) == NULL)
		goto done;

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64, b64_mem);

	while ((nr = BIO_read(b64, tmp, BUFSIZ)) > 0)
		if (fwrite(tmp, nr, 1, memstream) < 1)
			goto done;
	fclose(memstream);

	BIO_free_all(b64);

	if ((dec = mt_crypt(enc, len, t)) == NULL)
		goto done;

	if (memcmp(dec+len-BLKSIZ, "AAAA", BLKSIZ) == 0)
		res = true;

	free(enc);
	free(dec);
done:
	return res;
}

int
main(void)
{
	size_t len;
	char *buf, *enc, *dec, *token;
	uint16_t guess;
	bool found;

	len = arc4random_uniform(14) + 14;
	if ((buf = malloc(len)) == NULL)
		err(1, NULL);

	arc4random_buf(buf, len-14);
	memset(buf+len-14, 'A', 14);

	if ((enc = mt_crypt(buf, len, KEY)) == NULL)
		err(1, NULL);

	for (found = false, guess = 0;; guess++) {
		if ((dec = mt_crypt(enc, len, guess)) == NULL)
			err(1, NULL);
		if (memcmp(dec+len-BLKSIZ, "AAAA", BLKSIZ) == 0) {
			found = true;
			break;
		}
		if (guess == UINT16_MAX)
			break;
	}

	if (found)
		printf("Found key %u\n", guess);

	if ((token = get_token()) == NULL)
		err(1, NULL);

	printf("Token from %s timestamp\n", is_valid(token) ? "valid" : "invalid");

	exit(0);
}
