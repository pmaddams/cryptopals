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

	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);

	cbc_crypt_blk(&ctx, buf, key, enc);
	cbc_crypt_blk(&ctx, buf+BLKSIZ, key, enc);

	EVP_CIPHER_CTX_cleanup(&ctx);
}

int
main(void)
{
	uint8_t buf[BLKSIZ*2];
	size_t i, len;

	memset(buf, 1, BLKSIZ*2);

	cbc_crypt(buf, &len, KEY, 1);

	for (i = 0; i < BLKSIZ*2; i++)
		printf("%02hhx", buf[i]);
	putchar('\n');

	exit(0);
}
