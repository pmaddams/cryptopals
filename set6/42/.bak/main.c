#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "42.h"

uint8_t *
rsa_sign(RSA *rsa, uint8_t *buf, size_t len)
{
	uint8_t *tmp, *res, *asn;
	size_t rsa_size, asnlen;

	rsa_size = RSA_size(rsa);
	if ((tmp = malloc(rsa_size)) == NULL ||
	    (res = malloc(rsa_size)) == NULL ||

	    (asn = make_asn1(buf, len, &asnlen)) == NULL ||

	    RSA_padding_add_PKCS1_type_1(tmp, rsa_size, asn, asnlen) == 0 ||
	    RSA_private_encrypt(rsa_size, tmp, res, rsa, RSA_PKCS1_PADDING) == 0)
		goto fail;

	free(tmp);
	free(asn);

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
	uint8_t *dec, *asn, *p1, *p2;
	size_t rsa_size, asnlen;

	rsa_size = RSA_size(rsa);
	if ((dec = malloc(rsa_size)) == NULL ||

	    RSA_public_decrypt(rsa_size, sig, dec, rsa, RSA_PKCS1_PADDING) == 0 ||

	    (asn = make_asn1(buf, len, &asnlen)) == NULL)
		goto fail;

	for (p1 = &dec[0]; *p1++ != '\x00';)
		continue;
	for (p2 = &asn[1]; *p2++ != '\x00';)
		continue;

	if (memcmp(p1, p2, asnlen) != 0)
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
	uint8_t *sig;

	if ((rsa = RSA_new()) == NULL ||
	    (e = BN_new()) == NULL ||

	    BN_dec2bn(&e, E) == 0 ||

	    RSA_generate_key_ex(rsa, BITS, e, NULL) == 0 ||

	    (sig = rsa_sign(rsa, DATA, strlen(DATA))) == NULL)
		err(1, NULL);

	printf("%d\n", rsa_verify_weak(rsa, DATA, strlen(DATA), sig));

	exit(0);
}
