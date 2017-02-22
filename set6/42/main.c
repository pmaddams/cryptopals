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

uint8_t *
rsa_sign(RSA *rsa, uint8_t *buf, size_t len)
{
	size_t rsa_size, asnlen;
	uint8_t *res, *asn;

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
	size_t i, rsa_size, asnlen;
	uint8_t *res, *tmp, *asn;
	BN_CTX *ctx;
	BIGNUM *t1, *t2;

	rsa_size = RSA_size(rsa);
	if ((res = malloc(rsa_size)) == NULL ||
	    (tmp = malloc(rsa_size)) == NULL ||

	    (asn = make_asn1(buf, len, &asnlen)) == NULL)
		goto fail;

	memset(res, 0, rsa_size);
	res[1] = '\x01';
	for (i = 2; i < RSA_PKCS1_PADDING_SIZE-1; i++)
		res[i] = '\xff';
	memcpy(&res[RSA_PKCS1_PADDING_SIZE], asn, asnlen);

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((t1 = BN_CTX_get(ctx)) == NULL ||
	    (t2 = BN_CTX_get(ctx)) == NULL ||

	    BN_bin2bn(res, rsa_size, t1) == NULL ||
	    cubert(t1, t1, ctx) == 0)
		goto fail;

	tmp[0] = '\0';
	for (;;) {
		if (BN_exp(t2, t1, rsa->e, ctx) == 0 ||
		    BN_bn2bin(t2, tmp+1) == 0)
			goto fail;

		if (memcmp(tmp, res, RSA_PKCS1_PADDING_SIZE+asnlen) >= 0)
			break;

		if (BN_add(t1, t1, BN_value_one()) == 0)
			goto fail;
	}

	memset(res, 0, rsa_size);
	BN_bn2bin(t1, res+rsa_size-BN_num_bytes(t1));

	free(tmp);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return res;
fail:
	return NULL;
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
	uint8_t *sig, *sig2;

	len = strlen(DATA);

	if ((rsa = RSA_new()) == NULL ||
	    (e = BN_new()) == NULL ||

	    BN_dec2bn(&e, E) == 0 ||

	    RSA_generate_key_ex(rsa, BITS, e, NULL) == 0 ||

	    (sig = rsa_sign(rsa, DATA, len)) == NULL ||
	    (sig2 = rsa_forge(rsa, DATA, len)) == NULL)
		err(1, NULL);

	puts("genuine signature:");
	printf("strong verification %s\n", rsa_verify_strong(rsa, DATA, len, sig) ? "success" : "failure");
	printf("weak verification %s\n\n", rsa_verify_weak(rsa, DATA, len, sig) ? "success" : "failure");

	puts("forged signature:");
	printf("strong verification %s\n", rsa_verify_strong(rsa, DATA, len, sig2) ? "success" : "failure");
	printf("weak verification %s\n", rsa_verify_weak(rsa, DATA, len, sig2) ? "success" : "failure");

	exit(0);
}
