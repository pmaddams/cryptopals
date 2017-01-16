#include <endian.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define KEY	"YELLOW SUBMARINE"
#define BLKSIZ	16

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

int
ctr_crypt(uint8_t *buf, size_t len, uint64_t nonce, uint8_t *key)
{
	EVP_CIPHER_CTX ctx;
	size_t i, enclen;
	uint8_t *enc;
	uint64_t ctr;

	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);

	enclen = (len/BLKSIZ+1)*BLKSIZ;
	if ((enc = calloc(1, enclen)) == NULL)
		goto fail;
	memcpy(enc, buf, len);

	for (ctr = i = 0; i < enclen; ctr++, i += BLKSIZ)
		if (ctr_crypt_blk(&ctx, enc+i, nonce, ctr, key) == 0)
			goto fail;

	EVP_CIPHER_CTX_cleanup(&ctx);

	memcpy(buf, enc, len);
	free(enc);
	return 1;
fail:
	return 0;
}

int
main(void)
{
	const char *secret =
	    "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
	BIO *b64_mem, *b64, *bio_out;
	FILE *memstream;
	char *buf, tmp[BUFSIZ];
	size_t len;
	ssize_t nr;

	if ((b64_mem = BIO_new_mem_buf((char *) secret, strlen(secret))) == NULL ||
	    (b64 = BIO_new(BIO_f_base64())) == NULL ||
	    (memstream = open_memstream(&buf, &len)) == NULL)
		err(1, NULL);

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64, b64_mem);

	while ((nr = BIO_read(b64, tmp, BUFSIZ)) > 0)
		if (fwrite(tmp, nr, 1, memstream) < 1)
			err(1, NULL);
	fclose(memstream);

	BIO_free_all(b64);

	if ((ctr_crypt(buf, len, 0, KEY)) == 0)
		err(1, NULL);

	puts(buf);

	exit(0);
}
