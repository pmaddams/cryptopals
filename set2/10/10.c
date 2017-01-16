#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define KEY	"YELLOW SUBMARINE"
#define BLKSIZ	16

int
cbc_crypt_blk(EVP_CIPHER_CTX *ctxp, uint8_t *blk, uint8_t *vec, uint8_t *key, int enc)
{
	uint8_t tmp[BLKSIZ], out[BLKSIZ];
	int i, len;

	if (enc)
		for (i = 0; i < BLKSIZ; i++)
			blk[i] ^= vec[i];
	else
		memcpy(tmp, blk, BLKSIZ);

	if (EVP_CipherInit_ex(ctxp, EVP_aes_128_ecb(), NULL, key, NULL, enc) == 0 ||
	    EVP_CipherUpdate(ctxp, out, &len, blk, BLKSIZ) == 0)
		goto fail;

	if (enc)
		memcpy(vec, out, BLKSIZ);
	else
		for (i = 0; i < BLKSIZ; i++) {
			out[i] ^= vec[i];
			vec[i] = tmp[i];
		}

	memcpy(blk, out, BLKSIZ);
	return 1;
fail:
	return 0;
}

int
cbc_crypt(uint8_t *buf, size_t *lenp, uint8_t *key, int enc)
{
	EVP_CIPHER_CTX ctx;
	uint8_t *newp, pad, vec[BLKSIZ];
	size_t i, newlen;

	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);

	if (enc) {
		newlen = (*lenp/BLKSIZ+1)*BLKSIZ;
		if ((newp = realloc(buf, newlen+1)) == NULL)
			goto fail;
		buf = newp;
		pad = newlen-*lenp;
		while (*lenp < newlen)
			buf[(*lenp)++] = pad;
		buf[newlen] = '\0';
	}

	memset(vec, 0, BLKSIZ);
	for (i = 0; i < *lenp; i += BLKSIZ)
		if (cbc_crypt_blk(&ctx, buf+i, vec, key, enc) == 0)
			goto fail;

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

	BIO_free_all(bio);

	if (cbc_crypt(buf, &len, KEY, 0) == 0)
		err(1, NULL);

	puts(buf);

	exit(0);
}
