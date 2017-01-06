#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define KEY	"YELLOW SUBMARINE"

#define BLKSIZ	16

int
cbc_crypt_blk(EVP_CIPHER_CTX *ctxp, uint8_t *blk, uint8_t *key, int enc)
{
	uint8_t out[BLKSIZ];
	int outlen;

	EVP_CipherInit(ctxp, EVP_aes_128_ecb(), key, NULL, enc);
	EVP_CipherUpdate(ctxp, out, &outlen, blk, BLKSIZ);
	EVP_CipherFinal(ctxp, out, &outlen);

	memcpy(blk, out, BLKSIZ);
}

int
cbc_crypt(uint8_t *buf, size_t *lenp, uint8_t *key, int enc)
{
	EVP_CIPHER_CTX ctx;
	uint8_t *newp, rem;
	size_t i, newlen;

	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);

	if (*lenp % BLKSIZ) {
		newlen = (*lenp/BLKSIZ+1)*BLKSIZ;
		if ((newp = realloc(buf, newlen)) == NULL)
			goto fail;
		buf = newp;
		rem = newlen-*lenp;
		while (*lenp < newlen)
			buf[(*lenp)++] = rem;
	}

	for (i = 0; i < *lenp; i += BLKSIZ)
		cbc_crypt_blk(&ctx, buf+i, key, enc);

	EVP_CIPHER_CTX_cleanup(&ctx);

	return 1;
fail:
	return 0;
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
		if (fwrite(tmp, nr, 1, memstream) < 1)
			err(1, NULL);
	fclose(memstream);

	cbc_crypt(buf, &len, KEY, 0);

	fwrite(buf, len, 1, stdout);
	putchar('\n');

	exit(0);
}
