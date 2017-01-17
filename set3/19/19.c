#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "data.h"
#include "tab.h"

#define BLKSIZ 16

struct {
	uint8_t *buf;
	size_t len;
} enc[NDATA];

uint8_t *
encrypt(char *s, size_t *lenp, uint64_t nonce)
{
	static uint8_t key[BLKSIZ];
	BIO *b64_mem, *b64;
	FILE *memstream;
	char *buf, tmp[BUFSIZ], *in, *out;
	size_t i, buflen;
	ssize_t nr;
	int inlen, outlen;
	uint64_t ctr;
	EVP_CIPHER_CTX ctx;

	while (*key == '\0')
		arc4random_buf(key, BLKSIZ);

	if ((b64_mem = BIO_new_mem_buf(s, strlen(s))) == NULL ||
	    (b64 = BIO_new(BIO_f_base64())) == NULL ||
	    (memstream = open_memstream(&buf, &buflen)) == NULL)
		goto fail;

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64, b64_mem);

	while ((nr = BIO_read(b64, tmp, BUFSIZ)) > 0)
		if (fwrite(tmp, nr, 1, memstream) < 1)
			goto fail;
	fclose(memstream);

	BIO_free_all(b64);

	inlen = ((buflen-1)/BLKSIZ+1)*BLKSIZ;
	if ((in = malloc(inlen)) == NULL ||
	    (out = malloc(inlen+1)) == NULL)
		goto fail;

	for (ctr = i = 0; i < inlen; i += BLKSIZ, ctr++) {
		memcpy(in+i, &nonce, BLKSIZ/2);
		memcpy(in+i+BLKSIZ/2, &ctr, BLKSIZ/2);
	}

	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);

	if (EVP_EncryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key, NULL) == 0 ||
	    EVP_EncryptUpdate(&ctx, out, &outlen, in, inlen) == 0)
		goto fail;

	EVP_CIPHER_CTX_cleanup(&ctx);

	for (i = 0; i < buflen; i++)
		out[i] ^= buf[i];

	if (lenp != NULL)
		*lenp = outlen;

	free(in);
	free(buf);
	return out;
fail:
	return NULL;
}

int
make_enc(void)
{
	size_t i, len;
	uint8_t *buf;

	for (i = 0; i < NDATA; i++) {
		if ((buf = encrypt((char *) data[i], &len, 0)) == NULL)
			goto fail;
		enc[i].buf = buf;
		enc[i].len = len;
	}

	return 1;
fail:
	return 0;
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
		switch (c = *buf++) {
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

uint8_t
crack_byte(size_t i)
{
	size_t j;
	uint8_t buf[NDATA], cp[NDATA], c, found;
	float scr, best;

	for (j = 0; j < NDATA; j++)
		buf[j] = enc[j].buf[i];

	for (best = 0., found = c = 0;; c++) {
		memcpy(cp, buf, NDATA);
		xor(cp, c, NDATA);
		if ((scr = score(cp, NDATA)) > best) {
			best = scr;
			found = c;
		}
		if (c == UINT8_MAX)
			break;
	}

	return found;
}

int
main(void)
{
	size_t i, j, least;
	uint8_t *keystream;

	if (make_enc() == 0)
		err(1, NULL);

	least = enc[0].len;
	for (i = 1; i < NDATA; i++)
		if (enc[i].len < least)
			least = enc[i].len;

	if ((keystream = malloc(least)) == NULL)
		err(1, NULL);

	for (i = 0; i < least; i++)
		keystream[i] = crack_byte(i);

	for (i = 0; i < NDATA; i++) {
		for (j = 0; j < least; j++)
			enc[i].buf[j] ^= keystream[j];
		enc[i].buf[j] = '\0';

		puts(enc[i].buf);
	}

	exit(0);
}
