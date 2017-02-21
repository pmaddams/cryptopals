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
	uint8_t *asn1;
	size_t len;

	if ((rsa = RSA_new()) == NULL ||
	    (e = BN_new()) == NULL ||

	    BN_dec2bn(&e, E) == 0 ||

	    RSA_generate_key_ex(rsa, BITS, e, NULL) == 0 ||

	    (asn1 = make_asn1(DATA, strlen(DATA), &len)) == NULL)
		err(1, NULL);

	exit(0);
}
