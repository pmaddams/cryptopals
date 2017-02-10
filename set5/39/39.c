#include <err.h>
#include <stdio.h>

#include <openssl/bn.h>

BIGNUM *
invmod(BIGNUM *n, BIGNUM *modulus)
{
	BN_CTX *ctx;
	BIGNUM *res, *remainder, *quotient, *x0, *x1, *t0, *t1;

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

	if (BN_is_one(res)) {
		if (BN_mod(res, x0, modulus, ctx) == 0)
			goto fail;
	}
	BN_zero(t0);
	if (BN_cmp(res, t0) < 0)
		BN_add(res, modulus, res);

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
done:
	return res;
fail:
	return NULL;
}

int
main(int argc, char **argv)
{
	BIGNUM *a, *b, *res;
	char *buf;

	if (argc != 3) {
		fprintf(stderr, "usage: %s n1 n2\n", argv[0]);
		return 1;
	}

	a = b = NULL;
	if (BN_dec2bn(&a, argv[1]) == 0 ||
	    BN_dec2bn(&b, argv[2]) == 0 ||
	    (res = invmod(a, b)) == NULL ||
	    (buf = BN_bn2dec(res)) == NULL)
		err(1, NULL);

	puts(buf);

	return 0;
}
