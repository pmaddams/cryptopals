#include <err.h>
#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define KEY	"YELLOW SUBMARINE"

#define BLKSIZ	16

#define ENCRYPT	1
#define DECRYPT	0

int
cbc_crypt_blk(EVP_CIPHER_CTX *ctxp, uint8_t *blk, uint8_t *key, uint8_t *vec, int enc)
{
	static uint8_t out[BLKSIZ*2];
	size_t i, outlen;

	/*
	if (enc == ENCRYPT)
		for (i = 0; i < BLKSIZ; i++)
			blk[i] ^= vec[i];
	*/

	if (EVP_CipherInit_ex(ctxp, EVP_aes_128_ecb(), NULL, key, NULL, enc) == 0 ||
	    EVP_CipherUpdate(ctxp, out, &outlen, blk, BLKSIZ) == 0 ||
	    EVP_CipherFinal_ex(ctxp, out, &outlen) == 0)
		goto fail;

	EVP_CIPHER_CTX_cleanup(ctxp);

	/*
	if (enc == DECRYPT)
		for (i = 0; i < BLKSIZ; i++)
			out[i] ^= vec[i];
	*/

	memcpy(blk, out, BLKSIZ);
	return 1;
fail:
	return 0;
}

int
cbc_crypt(uint8_t *buf, size_t *lenp, uint8_t *key, int enc)
{
	EVP_CIPHER_CTX ctx;

	
}

int
main(void)
{
	return 0;
}
