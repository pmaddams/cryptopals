#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#define BITS 256

struct bb {
	RSA *rsa;
	BIGNUM *b;
	BIGNUM *c;
	BIGNUM *cprime;
	BIGNUM *s;
	BIGNUM *lower;
	BIGNUM *upper;
	size_t i;
};

int
bb_init(struct bb *bb, RSA *rsa, uint8_t *enc)
{
	size_t rsa_len;
	BN_CTX *ctx;
	BIGNUM *two, *three;

	rsa_len = RSA_size(rsa);

	bb->rsa = rsa;
	bb->i = 0;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((bb->b = BN_new()) == NULL ||
	    (bb->c = BN_new()) == NULL ||
	    (bb->cprime = BN_new()) == NULL ||
	    (bb->s = BN_new()) == NULL ||
	    (bb->lower = BN_new()) == NULL ||
	    (bb->upper = BN_new()) == NULL ||

	    (two = BN_CTX_get(ctx)) == NULL ||
	    (three = BN_CTX_get(ctx)) == NULL ||

	    BN_set_word(two, 2) == 0 ||
	    BN_set_word(three, 3) == 0 ||

	    BN_set_word(bb->b, 8*(rsa_len-2)) == 0 ||
	    BN_exp(bb->b, two, bb->b, ctx) == 0 ||

	    BN_bin2bn(enc, rsa_len, bb->c) == NULL ||

	    BN_mul(bb->lower, two, bb->b, ctx) == 0 ||
	    BN_mul(bb->upper, three, bb->b, ctx) == 0 ||
	    BN_sub(bb->upper, bb->upper, BN_value_one()) == 0)
		goto fail;

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return 1;
fail:
	return 0;
}

int
main(void)
{
	struct bb bb;
	RSA *rsa;
	BIGNUM *three;

	rsa = RSA_new();
	three = BN_new();

	BN_set_word(three, 3);
	RSA_generate_key_ex(rsa, BITS, three, NULL);
}
