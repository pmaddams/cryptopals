#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#define BITS 256

enum {
	PADDING_OK,
	PADDING_BAD,
	PADDING_ERR
};

struct bb {
	RSA *rsa;
	BIGNUM *b;
	BIGNUM *c0;
	BIGNUM *c;
	BIGNUM *s;
	BIGNUM *lower;
	BIGNUM *upper;
	size_t i;
};

const char *data = "kick it, CC";

uint8_t *
rsa_encrypt(RSA *rsa, char *buf)
{
	uint8_t *res;

	if ((res = malloc(RSA_size(rsa))) == NULL ||
	    RSA_public_encrypt(strlen(buf), buf, res, rsa, RSA_PKCS1_PADDING) == -1)
		goto fail;

	return res;
fail:
	return NULL;
}

int
rsa_check_padding(RSA *rsa, BIGNUM *c)
{
	static uint8_t *t1, *t2;
	static size_t rsa_len;

	if (t1 == NULL || t2 == NULL) {
		rsa_len = RSA_size(rsa);
		if ((t1 = malloc(rsa_len)) == NULL ||
		    (t2 = malloc(rsa_len)) == NULL)
			goto fail;
	}

	memset(t1, 0, rsa_len);
	if (BN_bn2bin(c, t1+rsa_len-BN_num_bytes(c)) == 0)
		goto fail;

	if (RSA_private_decrypt(rsa_len, t1, t2, rsa, RSA_NO_PADDING) == -1)
		goto fail;

	if (memcmp(t2, "\x00\x02", 2) == 0)
		return PADDING_OK;
	else
		return PADDING_BAD;
fail:
	return PADDING_ERR;
}

int
bb_interval_update(struct bb *bb, BIGNUM *lval, BIGNUM *uval)
{
	return BN_copy(bb->lower, lval) &&
	    BN_copy(bb->upper, uval);
}

int
bb_init(struct bb *bb, uint8_t *enc, RSA *rsa)
{
	size_t rsa_len;
	BN_CTX *ctx;
	BIGNUM *two, *three, *lower, *upper;

	rsa_len = RSA_size(rsa);
	bb->rsa = rsa;
	bb->i = 1;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((bb->b = BN_new()) == NULL ||
	    (bb->c0 = BN_new()) == NULL ||
	    (bb->c = BN_new()) == NULL ||
	    (bb->s = BN_new()) == NULL ||
	    (bb->lower = BN_new()) == NULL ||
	    (bb->upper = BN_new()) == NULL ||

	    (two = BN_CTX_get(ctx)) == NULL ||
	    (three = BN_CTX_get(ctx)) == NULL ||
	    (lower = BN_CTX_get(ctx)) == NULL ||
	    (upper = BN_CTX_get(ctx)) == NULL ||

	    BN_set_word(two, 2) == 0 ||
	    BN_set_word(three, 3) == 0 ||

	    BN_set_word(bb->b, 8*(rsa_len-2)) == 0 ||
	    BN_exp(bb->b, two, bb->b, ctx) == 0 ||

	    BN_bin2bn(enc, rsa_len, bb->c0) == NULL ||

	    BN_mul(lower, bb->b, two, ctx) == 0 ||
	    BN_mul(upper, bb->b, three, ctx) == 0 ||
	    BN_sub(upper, upper, BN_value_one()) == 0 ||

	    bb_interval_update(bb, lower, upper) == 0)
		goto fail;

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return 1;
fail:
	return 0;
}

int
bb_search(struct bb *bb)
{
	BN_CTX *ctx;
	BIGNUM *r, *two, *three, *t1, *t2, *t3, *smin, *smax;
	int padding;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if (bb->i == 1) {
		if ((t1 = BN_CTX_get(ctx)) == NULL)
			goto fail;

		if (BN_copy(bb->s, bb->rsa->n) == 0 ||
		    BN_set_word(t1, 3) == 0 ||
		    BN_mul(t1, t1, bb->b, ctx) == 0 ||
		    BN_div(bb->s, t1, bb->s, t1, ctx) == 0)
			goto fail;

		if (!BN_is_zero(t1))
			if (BN_add(bb->s, bb->s, BN_value_one()) == 0)
				goto fail;

		for (;;) {
			if (BN_mod_exp(bb->c, bb->s, bb->rsa->e, bb->rsa->n, ctx) == 0 ||
			    BN_mod_mul(bb->c, bb->c, bb->c0, bb->rsa->n, ctx) == 0)
				goto fail;

			if ((padding = rsa_check_padding(bb->rsa, bb->c)) == PADDING_ERR)
				goto fail;
			else if (padding == PADDING_OK)
				goto done;

			if (BN_add(bb->s, bb->s, BN_value_one()) == 0)
				goto fail;
		}
	} else {
		if ((r = BN_CTX_get(ctx)) == NULL ||
		    (two = BN_CTX_get(ctx)) == NULL ||
		    (three = BN_CTX_get(ctx)) == NULL ||
		    (t1 = BN_CTX_get(ctx)) == NULL ||
		    (t2 = BN_CTX_get(ctx)) == NULL ||
		    (smin = BN_CTX_get(ctx)) == NULL ||
		    (smax = BN_CTX_get(ctx)) == NULL ||

		    BN_copy(r, bb->s) == 0 ||
		    BN_set_word(two, 2) == 0 ||
		    BN_mul(r, r, two, ctx) == 0 ||
		    BN_mul(r, r, bb->upper, ctx) == 0 ||

		    BN_mul(t1, two, bb->b, ctx) == 0 ||
		    BN_sub(r, r, t1) == 0 ||

		    BN_div(r, NULL, r, bb->rsa->n, ctx) == 0)
			goto fail;

		for (;;) {
			if (BN_mul(t1, r, bb->rsa->n, ctx) == 0 ||

			    BN_mul(t2, two, bb->b, ctx) == 0 ||
			    BN_add(smin, t1, t2) == 0 ||
			    BN_div(smin, NULL, smin, bb->upper, ctx) == 0 ||

			    BN_set_word(three, 3) == 0 ||
			    BN_mul(t2, three, bb->b, ctx) == 0 ||
			    BN_add(smax, t1, t2) == 0 ||
			    BN_div(smax, NULL, smax, bb->lower, ctx) == 0 ||

			    BN_copy(bb->s, smin) == 0)
				goto fail;

			for (;;) {
				if (BN_mod_exp(bb->c, bb->s, bb->rsa->e, bb->rsa->n, ctx) == 0 ||
				    BN_mod_mul(bb->c, bb->c, bb->c0, bb->rsa->n, ctx) == 0)
					goto fail;

				if ((padding = rsa_check_padding(bb->rsa, bb->c)) == PADDING_ERR)
					goto fail;
				else if (padding == PADDING_OK)
					goto done;

				if (BN_cmp(bb->s, smax) >= 0)
					break;
				if (BN_add(bb->s, bb->s, BN_value_one()) == 0)
					goto fail;
			}
			if (BN_add(r, r, BN_value_one()) == 0)
				goto fail;
		}
	}
done:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return 1;
fail:
	return 0;
}

int
bb_generate_intervals(struct bb *bb)
{
	BN_CTX *ctx;
	BIGNUM *rmin, *rmax, *r, *two, *three, *t1, *t2,
	    *lower, *upper;
	size_t i;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((rmin = BN_CTX_get(ctx)) == NULL ||
	    (rmax = BN_CTX_get(ctx)) == NULL ||
	    (r = BN_CTX_get(ctx)) == NULL ||
	    (two = BN_CTX_get(ctx)) == NULL ||
	    (three = BN_CTX_get(ctx)) == NULL ||
	    (t1 = BN_CTX_get(ctx)) == NULL ||
	    (t2 = BN_CTX_get(ctx)) == NULL ||
	    (lower = BN_CTX_get(ctx)) == NULL ||
	    (upper = BN_CTX_get(ctx)) == NULL ||

	    BN_set_word(two, 2) == 0 ||
	    BN_set_word(three, 3) == 0)
		goto fail;

	if (BN_mul(t1, bb->lower, bb->s, ctx) == 0 ||
	    BN_mul(t2, three, bb->b, ctx) == 0 ||
	    BN_sub(rmin, t1, t2) == 0 ||
	    BN_add(rmin, rmin, BN_value_one()) == 0 ||
	    BN_div(rmin, t1, rmin, bb->rsa->n, ctx) == 0)
		goto fail;

	if (!BN_is_zero(t1))
		if (BN_add(rmin, rmin, BN_value_one()) == 0)
			goto fail;

	if (BN_mul(t1, bb->upper, bb->s, ctx) == 0 ||
	    BN_mul(t2, two, bb->b, ctx) == 0 ||
	    BN_sub(rmax, t1, t2) == 0 ||
	    BN_div(rmax, NULL, rmax, bb->rsa->n, ctx) == 0 ||

	    BN_copy(r, rmin) == 0)
		goto fail;

	if (BN_cmp(rmin, rmax) != 0)
		errx(1, "try again");

	for (;;) {
		if (BN_mul(t1, two, bb->b, ctx) == 0 ||
		    BN_mul(t2, r, bb->rsa->n, ctx) == 0 ||
		    BN_add(lower, t1, t2) == 0 ||
		    BN_div(lower, t1, lower, bb->s, ctx) == 0)
			goto fail;

		if (!BN_zero(t1))
			if (BN_add(lower, lower, BN_value_one()) == 0)
				goto fail;

		if (BN_cmp(lower, bb->lower) < 0)
			lower = bb->lower;

		if (BN_mul(t1, three, bb->b, ctx) == 0 ||
		    BN_sub(t1, t1, BN_value_one()) == 0 ||
		    BN_mul(t2, r, bb->rsa->n, ctx) == 0 ||
		    BN_add(upper, t1, t2) == 0 ||
		    BN_div(upper, NULL, upper, bb->s, ctx) == 0)
			goto fail;

		if (BN_cmp(upper, bb->upper) > 0)
			upper = bb->upper;

		if (bb_interval_update(bb, lower, upper) == 0)
			goto fail;

		if (BN_cmp(r, rmax) >= 0)
			break;

		if (BN_add(r, r, BN_value_one()) == 0)
			goto fail;
	}

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return 1;
fail:
	return 0;
}

char *
crack_rsa(RSA *rsa, uint8_t *enc)
{
	struct bb bb;
	size_t rsa_len;
	char *res;

	bb_init(&bb, enc, rsa);
	bb_search(&bb);
	bb_generate_intervals(&bb);

	rsa_len = RSA_size(rsa);
	if ((res = malloc(rsa_len+1)) == NULL)
		goto fail;

	while (BN_cmp(bb.lower, bb.upper) != 0) {
		bb.i++;
		bb_search(&bb);
		bb_generate_intervals(&bb);
	}

	BN_bn2bin(bb.lower, res);

	return res;
fail:
	return NULL;
}

int
main(void)
{
	RSA *rsa;
	BIGNUM *f4;
	uint8_t *enc;
	char *buf;

	if ((rsa = RSA_new()) == NULL ||
	    (f4 = BN_new()) == NULL ||

	    BN_set_word(f4, RSA_F4) == 0 ||
	    RSA_generate_key_ex(rsa, BITS, f4, NULL) == 0 ||

	    (enc = rsa_encrypt(rsa, (char *) data)) == NULL ||
	    (buf = crack_rsa(rsa, enc)) == NULL)
		err(1, NULL);

	puts(buf);

	exit(0);
}
