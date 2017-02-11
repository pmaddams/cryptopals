#include <openssl/bn.h>

BIGNUM *
invmod(BIGNUM *n, BIGNUM *modulus)
{
	BIGNUM *res, *remainder, *quotient, *x0, *x1, *t0, *t1;
	BN_CTX *ctx;

	if (BN_is_zero(n) || BN_is_zero(modulus))
		goto fail;
	if (BN_is_one(n) || BN_is_one(modulus)) {
		res = BN_dup(BN_value_one());
		goto done;
	}

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((res = BN_dup(n)) == NULL ||
	    (remainder = BN_CTX_get(ctx)) == NULL ||
	    (quotient = BN_CTX_get(ctx)) == NULL ||
	    (x0 = BN_CTX_get(ctx)) == NULL ||
	    (x1 = BN_CTX_get(ctx)) == NULL ||
	    (t0 = BN_CTX_get(ctx)) == NULL ||
	    (t1 = BN_CTX_get(ctx)) == NULL ||

	    BN_copy(remainder, modulus) == NULL ||
	    BN_one(x0) == 0 ||
	    BN_zero(x1) == 0)
		goto fail;

	while (!BN_is_zero(remainder)) {
		if (BN_div(quotient, t0, res, remainder, ctx) == 0 ||
		    BN_copy(res, remainder) == NULL ||
		    BN_copy(remainder, t0) == NULL ||

		    BN_copy(t0, x1) == NULL ||
		    BN_mul(t1, quotient, x1, ctx) == 0 ||
		    BN_sub(x1, x0, t1) == 0 ||
		    BN_copy(x0, t0) == NULL)
			goto fail;
	}

	if (!BN_is_one(res) ||
	    BN_mod(res, x0, modulus, ctx) == 0)
		goto fail;

	if (BN_is_negative(res))
		BN_add(res, modulus, res);

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
done:
	return res;
fail:
	return NULL;
}
