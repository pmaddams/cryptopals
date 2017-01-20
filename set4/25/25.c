#include <sys/types.h>

#include <endian.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define BLKSIZ 16

int
ctr_crypt_blk(EVP_CIPHER_CTX *ctxp, uint8_t *blk, uint64_t nonce, uint64_t ctr, uint8_t *key)
{
	uint8_t tmp[BLKSIZ], out[BLKSIZ];
	int i, len;

	nonce = htole64(nonce);
	ctr = htole64(ctr);

	memcpy(tmp, &nonce, BLKSIZ/2);
	memcpy(tmp+BLKSIZ/2, &ctr, BLKSIZ/2);

	if (EVP_EncryptInit_ex(ctxp, EVP_aes_128_ecb(), NULL, key, NULL) == 0 ||
	    EVP_EncryptUpdate(ctxp, out, &len, tmp, BLKSIZ) == 0)
		goto fail;

	for (i = 0; i < BLKSIZ; i++)
		blk[i] ^= out[i];

	return 1;
fail:
	return 0;
}

uint8_t *
ctr_crypt(uint8_t *in, size_t inlen, uint64_t nonce)
{
	static uint8_t key[BLKSIZ];
	EVP_CIPHER_CTX ctx;
	size_t i, outlen;
	uint8_t *out;
	uint64_t ctr;

	while (*key == '\0')
		arc4random_buf(key, BLKSIZ);

	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);

	outlen = (inlen/BLKSIZ+1)*BLKSIZ;
	if ((out = malloc(outlen)) == NULL)
		goto fail;
	memcpy(out, in, inlen);

	for (ctr = i = 0; i < outlen; i += BLKSIZ, ctr++)
		if (ctr_crypt_blk(&ctx, out+i, nonce, ctr, key) == 0)
			goto fail;

	EVP_CIPHER_CTX_cleanup(&ctx);

	out[inlen] = '\0';
	return out;
fail:
	return NULL;
}

char *
edit(uint8_t *enc, size_t enclen, uint8_t *buf, size_t buflen, size_t offset)
{
	uint8_t *dec, *newp;
	size_t declen;

	if ((dec = ctr_crypt(enc, enclen, 0)) == NULL)
		goto fail;

	if (buflen + offset > enclen) {
		if ((newp = realloc(dec, buflen+offset)) == NULL)
			goto fail;
		dec = newp;
		declen = buflen + offset;
	} else
		declen = enclen;

	memcpy(dec+offset, buf, buflen);

	if ((newp = ctr_crypt(dec, declen, 0)) == NULL)
		goto fail;

	return newp;
fail:
	return NULL;
}

int
main(void)
{
	BIO *bio, *b64, *cip, *bio_out;
	FILE *memstream;
	char *buf, tmp[BUFSIZ];
	size_t len;
	ssize_t nr;
	uint8_t *enc, *dec;

	if ((bio = BIO_new_fp(stdin, BIO_NOCLOSE)) == NULL ||
	    (b64 = BIO_new(BIO_f_base64())) == NULL ||
	    (cip = BIO_new(BIO_f_cipher())) == NULL ||
	    (memstream = open_memstream(&buf, &len)) == NULL ||
	    (bio_out = BIO_new_fp(memstream, BIO_NOCLOSE)) == NULL)
		err(1, NULL);

	BIO_set_cipher(cip, EVP_aes_128_ecb(), "YELLOW SUBMARINE", NULL, 0);
	BIO_push(b64, bio);
	BIO_push(cip, bio_out);

	while ((nr = BIO_read(b64, tmp, BUFSIZ)) > 0)
		if (BIO_write(cip, tmp, nr) < nr)
			err(1, NULL);

	BIO_flush(cip);
	fclose(memstream);
	BIO_free_all(b64);
	BIO_free_all(cip);

	if ((enc = ctr_crypt(buf, len, 0)) == NULL ||
	    (dec = edit(enc, len, enc, len, 0)) == NULL)
		err(1, NULL);

	puts(dec);

	exit(0);
}
