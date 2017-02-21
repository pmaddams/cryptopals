#include <sys/types.h>

#include <err.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "42.h"

void
putx(uint8_t *buf, size_t len)
{
	while (len--)
		printf("%02hhx", *buf++);
	putchar('\n');
}

uint8_t *
rsa_sign(RSA *rsa, uint8_t *buf, size_t len)
{
	SHA2_CTX ctx;
	uint8_t *res, hash[SHA256_DIGEST_LENGTH];
	size_t rsa_size;

	SHA256Init(&ctx);
	SHA256Update(&ctx, buf, len);
	SHA256Final(hash, &ctx);

	rsa_size = RSA_size(rsa);
	if ((res = malloc(rsa_size)) == NULL ||

	    RSA_private_encrypt(SHA256_DIGEST_LENGTH, hash, res, rsa, RSA_PKCS1_PADDING) == 0)
		goto fail;

	return res;
fail:
	return NULL;
}

uint8_t *
rsa_forge(RSA *rsa, uint8_t *buf, size_t len)
{
}

int
rsa_verify_strong(RSA *rsa, uint8_t *buf, size_t len, uint8_t *sig)
{
}

int
rsa_verify_weak(RSA *rsa, uint8_t *buf, size_t len, uint8_t *sig)
{
	uint8_t *dec, *asn, *p;
	size_t rsa_size, asnlen;

	rsa_size = RSA_size(rsa);
	if ((dec = malloc(rsa_size)) == NULL ||

	    RSA_public_decrypt(rsa_size, sig, dec, rsa, RSA_PKCS1_PADDING) == 0 ||

	    (asn = make_asn1(buf, len, &asnlen)) == NULL ||
	    memmem(asn, asnlen, dec, SHA256_DIGEST_LENGTH) == NULL)
		goto fail;

	free(dec);
	free(asn);

	return 1;
fail:
	return 0;
}

int
main(void)
{
	RSA *rsa;
	BIGNUM *e;
	uint8_t *sig, *sig2;

	if ((rsa = RSA_new()) == NULL ||
	    (e = BN_new()) == NULL ||

	    BN_dec2bn(&e, E) == 0 ||

	    RSA_generate_key_ex(rsa, BITS, e, NULL) == 0 ||

	    (sig = rsa_sign(rsa, DATA, strlen(DATA))) == NULL)
		err(1, NULL);

	exit(0);
}
