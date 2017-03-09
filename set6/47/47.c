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

struct bb {
	struct interval *m;
	size_t m_len;
	size_t i;
	BIGNUM *b;
	BIGNUM *s;
};

const char *data = "kick it, CC";

int
bb_init(struct bb *bb)
{
}

/*
RSA_padding_check_PKCS1_type_2
*/

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
