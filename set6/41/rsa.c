#include "41.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#define E	"3"
#define BITS	2048

static BIGNUM *
invmod(BIGNUM *bn, BIGNUM *modulus)
{
	BIGNUM *res, *remainder, *quotient, *x1, *x2, *t1, *t2;
	BN_CTX *ctx;

	if (BN_is_zero(bn) || BN_is_zero(modulus))
		goto fail;
	if (BN_is_one(bn) || BN_is_one(modulus)) {
		res = BN_dup(BN_value_one());
		goto done;
	}

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((res = BN_dup(bn)) == NULL ||
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
	    BN_nnmod(res, x1, modulus, ctx) == 0)
		goto fail;

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
done:
	return res;
fail:
	return NULL;
}

int
rsa_init(struct rsa *rsa)
{
	BN_CTX *ctx;
	BIGNUM *totient, *t1, *t2;

#ifdef VERBOSE
	fprintf(stderr, "initializing, please wait...");
#endif

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	memset(rsa, 0, sizeof(*rsa));

	if ((rsa->p = BN_new()) == NULL ||
	    (rsa->q = BN_new()) == NULL ||
	    (rsa->n = BN_new()) == NULL ||

	    (totient = BN_CTX_get(ctx)) == NULL ||
	    (t1 = BN_CTX_get(ctx)) == NULL ||
	    (t2 = BN_CTX_get(ctx)) == NULL ||

	    BN_generate_prime_ex(rsa->p, BITS, 0, NULL, NULL, NULL) == 0 ||
	    BN_generate_prime_ex(rsa->q, BITS, 0, NULL, NULL, NULL) == 0 ||

	    BN_mul(rsa->n, rsa->p, rsa->q, ctx) == 0 ||

	    BN_dec2bn(&rsa->e, E) == 0 ||

	    BN_sub(t1, rsa->p, BN_value_one()) == 0 ||
	    BN_sub(t2, rsa->q, BN_value_one()) == 0 ||
	    BN_mul(totient, t1, t2, ctx) == 0 ||
	    (rsa->d = invmod(rsa->e, totient)) == NULL)
		goto fail;

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

#ifdef VERBOSE
	fprintf(stderr, "done.\n");
#endif

	return 1;
fail:
	return 0;
}

BIGNUM *
rsa_crypt(struct rsa *rsa, BIGNUM *in, int enc)
{
	BN_CTX *ctx;
	BIGNUM *out;

	if ((ctx = BN_CTX_new()) == NULL ||
	    (out = BN_new()) == NULL ||
	    BN_mod_exp(out, in, enc ? rsa->e : rsa->d, rsa->n, ctx) == 0)
		goto fail;

	BN_CTX_free(ctx);
	return out;
fail:
	return NULL;
}
