#include <sys/types.h>

#include <endian.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define BLKSIZ	16

int
ctr_crypt_blk(uint8_t *blk, uint64_t nonce, uint64_t ctr)
{
	static uint8_t key[BLKSIZ];
	EVP_CIPHER_CTX ctx;
	uint8_t tmp[BLKSIZ], out[BLKSIZ];
	int i, len;

	while (*key == '\0')
		arc4random_buf(key, BLKSIZ);

	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);

	nonce = htole64(nonce);
	ctr = htole64(ctr);

	memcpy(tmp, &nonce, BLKSIZ/2);
	memcpy(tmp+BLKSIZ/2, &ctr, BLKSIZ/2);

	if (EVP_EncryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key, NULL) == 0 ||
	    EVP_EncryptUpdate(&ctx, out, &len, tmp, BLKSIZ) == 0)
		goto fail;

	for (i = 0; i < BLKSIZ; i++)
		blk[i] ^= out[i];

	EVP_CIPHER_CTX_cleanup(&ctx);

	return 1;
fail:
	return 0;
}

int
edit()
{

}

int
main()
{

}
