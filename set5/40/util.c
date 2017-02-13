#include <openssl/bn.h>

#include "40.h"

int
cubert(BIGNUM *res, BIGNUM *a, BN_CTX *ctx)
{
	BIGNUM *out, *two, *three, *t1, *t2;

	if ((out = BN_CTX_get(ctx)) == NULL ||
	    (two = BN_CTX_get(ctx)) == NULL ||
	    (three = BN_CTX_get(ctx)) == NULL ||
	    (t1 = BN_CTX_get(ctx)) == NULL ||
	    (t2 = BN_CTX_get(ctx)) == NULL ||

	    BN_copy(out, a) == NULL ||
	    BN_dec2bn(&two, "2") == 0 ||
	    BN_dec2bn(&three, "3") == 0)
		goto fail;

	for (;;) {
		BN_exp(t1, out, two, ctx);
		BN_div(t1, NULL, a, t1, ctx);

		BN_mul(t2, out, two, ctx);

		BN_add(t1, t1, t2);
		BN_div(t1, NULL, t1, three, ctx);

		if (BN_cmp(out, t1) == 0)
			break;
		if (BN_copy(out, t1) == NULL)
			goto fail;
	}

	return BN_copy(res, out) != NULL;
fail:
	return 0;
}

int
invmod(BIGNUM *res, BIGNUM *a, BIGNUM *modulus, BN_CTX *ctx)
{
	BIGNUM *out, *remainder, *quotient, *x1, *x2, *t1, *t2;

	if (BN_is_zero(a) || BN_is_zero(modulus))
		goto fail;
	if (BN_is_one(a) || BN_is_one(modulus))
		return BN_copy(res, BN_value_one()) != NULL;

	if ((out = BN_CTX_get(ctx)) == NULL ||
	    (remainder = BN_CTX_get(ctx)) == NULL ||
	    (quotient = BN_CTX_get(ctx)) == NULL ||
	    (x1 = BN_CTX_get(ctx)) == NULL ||
	    (x2 = BN_CTX_get(ctx)) == NULL ||
	    (t1 = BN_CTX_get(ctx)) == NULL ||
	    (t2 = BN_CTX_get(ctx)) == NULL ||

	    BN_copy(out, a) == NULL ||
	    BN_copy(remainder, modulus) == NULL ||
	    BN_one(x1) == 0 ||
	    BN_zero(x2) == 0)
		goto fail;

	while (!BN_is_zero(remainder)) {
		if (BN_div(quotient, t1, out, remainder, ctx) == 0 ||
		    BN_copy(out, remainder) == NULL ||
		    BN_copy(remainder, t1) == NULL ||

		    BN_copy(t1, x2) == NULL ||
		    BN_mul(t2, quotient, x2, ctx) == 0 ||
		    BN_sub(x2, x1, t2) == 0 ||
		    BN_copy(x1, t1) == NULL)
			goto fail;
	}

	if (!BN_is_one(out) ||
	    BN_nnmod(out, x1, modulus, ctx) == 0)
		goto fail;

	return BN_copy(res, out) != NULL;
fail:
	return 0;
}
