#include <err.h>

#include <openssl/bn.h>

BIGNUM *
invmod(BIGNUM *a, BIGNUM *modulus)
{
	BIGNUM *res, *remainder, *quotient, *x1, *x2, *t1, *t2;
	BN_CTX *ctx;

	if (BN_is_zero(a) || BN_is_zero(modulus))
		goto fail;
	if (BN_is_one(a) || BN_is_one(modulus)) {
		res = BN_dup(BN_value_one());
		goto done;
	}

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((res = BN_dup(a)) == NULL ||
	    (remainder = BN_CTX_get(ctx)) == NULL ||
	    (quotient = BN_CTX_get(ctx)) == NULL ||
	    (x1 = BN_CTX_get(ctx)) == NULL ||
	    (x2 = BN_CTX_get(ctx)) == NULL ||
	    (t1 = BN_CTX_get(ctx)) == NULL ||
	    (t2 = BN_CTX_get(ctx)) == NULL ||

	    BN_copy(remainder, modulus) == NULL ||
	    BN_one(x1) == 0 ||
	    BN_zero(x2) == 0)
		goto fail;

	while (!BN_is_zero(remainder)) {
		if (BN_div(quotient, t1, res, remainder, ctx) == 0 ||
		    BN_copy(res, remainder) == NULL ||
		    BN_copy(remainder, t1) == NULL ||

		    BN_copy(t1, x2) == NULL ||
		    BN_mul(t2, quotient, x2, ctx) == 0 ||
		    BN_sub(x2, x1, t2) == 0 ||
		    BN_copy(x1, t1) == NULL)
			goto fail;
	}

	if (!BN_is_one(res) ||
	    BN_mod(res, x1, modulus, ctx) == 0)
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

BIGNUM *
cubert(BIGNUM *a)
{
	BN_CTX *ctx;
	BIGNUM *res, *two, *three, *t1, *t2;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((res = BN_new()) == NULL ||
	    (two = BN_CTX_get(ctx)) == NULL ||
	    (three = BN_CTX_get(ctx)) == NULL ||
	    (t1 = BN_CTX_get(ctx)) == NULL ||
	    (t2 = BN_CTX_get(ctx)) == NULL ||

	    BN_copy(res, a) == 0 ||
	    BN_dec2bn(&two, "2") == 0 ||
	    BN_dec2bn(&three, "3") == 0)
		goto fail;

	for (;;) {
		BN_exp(t1, res, two, ctx);
		BN_div(t1, NULL, a, t1, ctx);

		BN_mul(t2, res, two, ctx);

		BN_add(t1, t1, t2);
		BN_div(t1, NULL, t1, three, ctx);

		if (BN_cmp(res, t1) == 0)
			break;
		if (BN_copy(res, t1) == NULL)
			goto fail;
	}

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return res;
fail:
	return NULL;
}

int
main(void)
{
	BIGNUM *a, *b;
	char *s;

	if ((a = BN_new()) == NULL ||
	    BN_dec2bn(&a, "12167") == 0 ||
	    (b = cubert(a)) == NULL ||
	    (s = BN_bn2dec(b)) == NULL)
		err(1, NULL);

	puts(s);

	return 0;
}
