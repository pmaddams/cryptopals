#include <sys/types.h>

#include <endian.h>
#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#define MATCH	";admin=true;"
#define CLOAK	29

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

bool
is_admin(uint8_t *buf, size_t len)
{
	return memmem(buf, len, MATCH, strlen(MATCH)) ? true : false;
}

int
main(void)
{

}
