#include <endian.h>
#include <err.h>
#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define KEY	"YELLOW SUBMARINE"
#define BLKSIZ	16

void
ctr_crypt_blk(EVP_CIPHER_CTX *ctxp, uint8_t *blk, uint64_t nonce, uint64_t ctr, uint8_t *key, int enc)
{
	uint8_t tmp[BLKSIZ];

	nonce = htole64(nonce);
	ctr = htole64(ctr);

	
}
