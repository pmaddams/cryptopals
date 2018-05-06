#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

uint8_t *
encrypt(uint8_t *in, size_t inlen, size_t *outlenp)
{
	const char *secret =
	    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
	    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
	    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
	    "YnkK";
	static uint8_t key[16], *prefix;
	static size_t pfxlen;
	BIO *b64_mem, *b64, *cip, *bio_out;
	FILE *memstream;
	char *out, buf[BUFSIZ];
	size_t outlen;
	ssize_t nr;

	while (*key == '\0')
		arc4random_buf(key, 16);

	if (prefix == NULL) {
		pfxlen = arc4random_uniform(16)+1;
		if ((prefix = malloc(pfxlen)) == NULL)
			goto fail;
		arc4random_buf(prefix, pfxlen);
	}

	if ((b64_mem = BIO_new_mem_buf((char *) secret, strlen(secret))) == NULL ||
	    (b64 = BIO_new(BIO_f_base64())) == NULL)
		goto fail;

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64, b64_mem);

	if ((memstream = open_memstream(&out, &outlen)) == NULL ||
	    (bio_out = BIO_new_fp(memstream, BIO_NOCLOSE)) == NULL ||
	    (cip = BIO_new(BIO_f_cipher())) == NULL)
		goto fail;

	BIO_set_cipher(cip, EVP_aes_128_ecb(), key, NULL, 1);
	BIO_push(cip, bio_out);

	if (BIO_write(cip, prefix, pfxlen) < pfxlen ||
	    BIO_write(cip, in, inlen) < inlen)
		goto fail;

	while ((nr = BIO_read(b64, buf, BUFSIZ)) > 0)
		if (BIO_write(cip, buf, nr) < nr)
			goto fail;
	BIO_flush(cip);
	fclose(memstream);

	BIO_free_all(b64);
	BIO_free_all(cip);

	if (outlenp != NULL)
		*outlenp = outlen;

	return out;
fail:
	return NULL;
}

int
crack_params(size_t *blksizp, size_t *offsetp)
{
	uint8_t buf[BUFSIZ], *enc1, *enc2, *sav;
	size_t i, j, len1, len2, blksiz, offset;

	if ((enc1 = encrypt("", 0, &len1)) == NULL)
		goto fail;

	for (i = 0; i < BUFSIZ; i++) {
		buf[i] = 'A';
		if ((enc2 = encrypt(buf, i+1, &len2)) == NULL)
			goto fail;
		if (len2 > len1)
			break;
		free(enc2);
	}

	blksiz = len2 - len1;

	for (i = 0; i < len1; i += blksiz)
		if (memcmp(enc1+i, enc2+i, blksiz) != 0)
			break;

	free(enc2);

	if ((sav = calloc(1, blksiz)) == NULL)
		goto fail;

	for (j = 0; j < BUFSIZ; j++) {
		buf[j] = 'A';
		if ((enc2 = encrypt(buf, j+1, &len2)) == NULL)
			goto fail;
		if (memcmp(sav, enc2+i, blksiz) == 0)
			break;
		memcpy(sav, enc2+i, blksiz);
		free(enc2);
	}

	offset = i + blksiz - j;

	free(enc2);
	free(sav);

	*blksizp = blksiz;
	*offsetp = offset;
	return 1;
fail:
	return 0;
}

bool
is_ecb(size_t blksiz, size_t offset)
{
	bool res;
	size_t gap;
	uint8_t *in, *out;

	res = false;
	gap = blksiz-(offset%blksiz);

	if ((in = malloc(gap+blksiz*2)) == NULL)
		goto done;
	memset(in, 'A', gap+blksiz*2);

	if ((out = encrypt(in, gap+blksiz*2, NULL)) == NULL)
		goto done;

	if (memcmp(out+offset+gap, out+offset+gap+blksiz, blksiz) == 0)
		res = true;

	free(in);
	free(out);
done:
	return res;
}

uint8_t *
crack_secret(size_t blksiz, size_t offset)
{
	uint8_t *enc, *in, *out, c;
	size_t i, gap, datalen, inlen;

	if ((enc = encrypt("", 0, &datalen)) == NULL)
		goto fail;

	gap = blksiz - (offset % blksiz);
	datalen = datalen - offset - gap;
	inlen = gap + datalen + blksiz - 1;

	if ((in = malloc(inlen)) == NULL ||
	    (out = malloc(datalen+1)) == NULL)
		goto fail;

	memset(in+gap, 'A', blksiz-1);
	memset(in+gap+datalen, 'A', blksiz-1);

	for (i = 0; i < datalen; i++) {
		for (c = 0; c < CHAR_MAX; c++) {
			in[gap+blksiz-1] = c;
			if ((enc = encrypt(in, inlen, NULL)) == NULL)
				goto fail;
			if (memcmp(enc+offset+gap, enc+offset+gap+datalen, blksiz) == 0) {
				free(enc);
				out[i] = c;
				memmove(in+gap, in+gap+1, blksiz-1);
				inlen--;
				break;
			}
			free(enc);
		}
		if (c == CHAR_MAX)
			break;
	}
	out[i] = '\0';
	return out;
fail:
	return NULL;
}

int
main(void)
{
	size_t blksiz, offset;
	char *s;

	if (crack_params(&blksiz, &offset) == 0)
		err(1, NULL);

	if (!is_ecb(blksiz, offset))
		errx(1, "ECB required");

	if ((s = crack_secret(blksiz, offset)) == NULL)
		err(1, NULL);

	puts(s);

	exit(0);
}
