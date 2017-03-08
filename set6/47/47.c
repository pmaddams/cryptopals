#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#define BITS 256

struct interval {
	BIGNUM *lower;
	BIGNUM *upper;
};

const char *data = "kick it, CC";

uint8_t *
rsa_encrypt(RSA *rsa, char *buf)
{
	uint8_t *res;

	if ((res = malloc(RSA_size(rsa))) == NULL ||
	    RSA_public_encrypt(strlen(buf), buf, res, rsa, RSA_PKCS1_PADDING) == 0)
		goto fail;

	return res;
fail:
	return NULL;
}

int
check_padding(RSA *rsa, char *enc)
{
}

int
main(void)
{
	RSA *rsa;
	BIGNUM *f4;

	if ((rsa = RSA_new()) == NULL ||
	    (f4 = BN_new()) == NULL ||

	    BN_set_word(f4, RSA_F4) == 0 ||
	    RSA_generate_key_ex(rsa, BITS, f4, NULL) == 0)
		err(1, NULL);
}
