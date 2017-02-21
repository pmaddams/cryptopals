#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "42.h"

char *
rsa_sign(RSA *rsa, uint8_t *buf, size_t len)
{
}

char *
rsa_forge(RSA *rsa, uint8_t *buf, size_t len)
{
}

int
rsa_verify(RSA *rsa, char *sig)
{
}

int
main(void)
{
	RSA *rsa;
	BIGNUM *e;

	if ((rsa = RSA_new()) == NULL ||
	    (e = BN_new()) == NULL ||

	    BN_dec2bn(&e, E) == 0 ||

	    RSA_generate_key_ex(rsa, BITS, e, NULL) == 0)
		err(1, NULL);

	asn1_sign(DATA, strlen(DATA), NULL);

	exit(0);
}
