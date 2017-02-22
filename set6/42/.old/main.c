#include <sys/types.h>

#include <err.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/objects.h>
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
	uint8_t *res, *asn;
	size_t rsa_size, asnlen;

	rsa_size = RSA_size(rsa);
	if ((res = malloc(rsa_size)) == NULL ||

	    (asn = make_asn1(buf, len, &asnlen)) == NULL ||

	    RSA_private_encrypt(asnlen, asn, res, rsa, RSA_PKCS1_PADDING) == 0)
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
	SHA2_CTX ctx;
	uint8_t hash[SHA256_DIGEST_LENGTH];

	SHA256Init(&ctx);
	SHA256Update(&ctx, buf, len);
	SHA256Final(hash, &ctx);

	return RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, sig, RSA_size(rsa), rsa);
}

int
rsa_verify_weak(RSA *rsa, uint8_t *buf, size_t len, uint8_t *sig)
{
	uint8_t *dec, *asn;
	size_t rsa_size, asnlen;

	rsa_size = RSA_size(rsa);
	if ((dec = malloc(rsa_size)) == NULL ||

	    RSA_public_decrypt(rsa_size, sig, dec, rsa, RSA_PKCS1_PADDING) == 0 ||

	    (asn = make_asn1(buf, len, &asnlen)) == NULL ||
	    memcmp(dec, asn, asnlen) != 0)
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
	size_t len;
	RSA *rsa;
	BIGNUM *e;
	uint8_t *sig;

	len = strlen(DATA);

	if ((rsa = RSA_new()) == NULL ||
	    (e = BN_new()) == NULL ||

	    BN_dec2bn(&e, E) == 0 ||

	    RSA_generate_key_ex(rsa, BITS, e, NULL) == 0 ||

	    (sig = rsa_sign(rsa, DATA, len)) == NULL)
		err(1, NULL);

	puts(rsa_verify_weak(rsa, DATA, len, sig) ? "success" : "failure");
	puts(rsa_verify_strong(rsa, DATA, len, sig) ? "success" : "failure");

	exit(0);
}
