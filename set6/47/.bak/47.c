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

struct interval {
	BIGNUM *lower;
	BIGNUM *upper;
};

struct bb {
	RSA *rsa;
	BIGNUM *b;
	BIGNUM *c0;
	BIGNUM *ci;
	BIGNUM *s0;
	BIGNUM *si;
	struct interval **m[2];
	size_t m_len[2];
	size_t i;
};

const char *data = "kick it, CC";

void
bb_debug(struct bb *bb)
{
	size_t i;

	printf("b: ");
	BN_print_fp(stdout, bb->b);
	putchar('\n');

	printf("c0: ");
	BN_print_fp(stdout, bb->c0);
	putchar('\n');

	printf("ci: ");
	BN_print_fp(stdout, bb->ci);
	putchar('\n');

	printf("s0: ");
	BN_print_fp(stdout, bb->s0);
	putchar('\n');

	printf("si: ");
	BN_print_fp(stdout, bb->si);
	putchar('\n');

	puts("{");
	for (i = 0; i < bb->m_len[0]; i++) {
		puts("\t[");
		printf("\tlower: ");
		BN_print_fp(stdout, bb->m[0][i]->lower);
		putchar('\n');

		printf("\tupper: ");
		BN_print_fp(stdout, bb->m[0][i]->upper);
		putchar('\n');
		puts("\t]");

		if (i < bb->m_len[0]-1)
			putchar('\n');
	}
	puts("}");

	printf("i: %u\n", bb->i);
}

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

	if (BN_bn2bin(c, t1) == 0)
		goto fail;

	if (RSA_private_decrypt(rsa_len, t1, t2, rsa, RSA_PKCS1_PADDING) != -1)
		return PADDING_OK;
	else
		return PADDING_BAD;
fail:
	return PADDING_ERR;
}

int
bb_interval_update(struct bb *bb, BIGNUM *lval, BIGNUM *uval)
{
	struct interval **pp, *p;
	BIGNUM *lower, *upper;

	if ((pp = reallocarray(bb->m[1], bb->m_len[1]+1, sizeof(*bb->m[1]))) == NULL ||
	    (p = malloc(sizeof(*p))) == NULL ||

	    (lower = BN_new()) == NULL ||
	    (upper = BN_new()) == NULL ||

	    BN_copy(lower, lval) == 0 ||
	    BN_copy(upper, uval) == 0)
		goto fail;

	p->lower = lower;
	p->upper = upper;

	bb->m[1] = pp;
	bb->m[1][bb->m_len[1]++] = p;

	return 1;
fail:
	return 0;
}

void
bb_interval_final(struct bb *bb)
{
	size_t i;

	for (i = 0; i < bb->m_len[0]; i++) {
		BN_free(bb->m[0][i]->lower);
		BN_free(bb->m[0][i]->upper);
		free(bb->m[0][i]);
	}
	free(bb->m[0]);

	bb->m[0] = bb->m[1];
	bb->m_len[0] = bb->m_len[1];

	bb->m[1] = NULL;
	bb->m_len[1] = 0;
}

int
bb_init(struct bb *bb, uint8_t *enc, RSA *rsa)
{
	size_t rsa_len;
	BN_CTX *ctx;
	BIGNUM *two, *three, *lower, *upper;

	rsa_len = RSA_size(rsa);
	bb->rsa = rsa;
	bb->m[0] = bb->m[1] = NULL;
	bb->m_len[0] = bb->m_len[1] = 0;
	bb->i = 1;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((bb->b = BN_new()) == NULL ||
	    (bb->c0 = BN_new()) == NULL ||
	    (bb->ci = BN_new()) == NULL ||
	    (bb->s0 = BN_new()) == NULL ||
	    (bb->si = BN_new()) == NULL ||

	    (two = BN_CTX_get(ctx)) == NULL ||
	    (three = BN_CTX_get(ctx)) == NULL ||
	    (lower = BN_CTX_get(ctx)) == NULL ||
	    (upper = BN_CTX_get(ctx)) == NULL ||

	    BN_set_word(two, 2) == 0 ||
	    BN_set_word(three, 3) == 0 ||

	    BN_set_word(bb->b, 8*(rsa_len-2)) == 0 ||
	    BN_exp(bb->b, two, bb->b, ctx) == 0 ||

	    BN_bin2bn(enc, rsa_len, bb->c0) == NULL ||

	    BN_one(bb->s0) == 0 ||

	    BN_mul(lower, bb->b, two, ctx) == 0 ||
	    BN_mul(upper, bb->b, three, ctx) == 0 ||
	    BN_mul(upper, upper, BN_value_one(), ctx) == 0 ||

	    bb_interval_update(bb, upper, lower) == 0)
		goto fail;
	bb_interval_final(bb);

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
	BIGNUM *r, *rmin, *rmax;
	int padding;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((r = BN_CTX_get(ctx)) == NULL ||
	    (rmin = BN_CTX_get(ctx)) == NULL ||
	    (rmax = BN_CTX_get(ctx)) == NULL)
		goto fail;

	if (bb->i == 1) {
		if (BN_copy(bb->si, bb->s0) == 0)
			goto fail;
		for (;;) {
			if (BN_mod_exp(bb->ci, bb->si, bb->rsa->e, bb->rsa->n, ctx) == 0 ||
			    BN_mod_mul(bb->ci, bb->ci, bb->c0, bb->rsa->n, ctx) == 0)
				goto fail;

			if ((padding = rsa_check_padding(bb->rsa, bb->ci)) == PADDING_ERR)
				goto fail;
			else if (padding == PADDING_OK)
				break;

			if (BN_add(bb->si, bb->si, BN_value_one()) == 0)
				goto fail;
		}
	} else if (0) {
		;
	} else {
		;
	}

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

	for (i = 0; i < bb->m_len[0]; i++) {
		BN_mul(t1, bb->m[0][i]->lower, bb->si, ctx);
		BN_mul(t2, three, bb->b, ctx);
		BN_sub(rmin, t1, t2);
		BN_add(rmin, rmin, BN_value_one());
		BN_div(rmin, NULL, rmin, bb->rsa->n, ctx);

		BN_mul(t1, bb->m[0][i]->upper, bb->si, ctx);
		BN_mul(t2, two, bb->b, ctx);
		BN_sub(rmax, t1, t2);
		BN_div(rmax, NULL, rmax, bb->rsa->n, ctx);

		BN_copy(r, rmin);
		for (;;) {
			if (BN_mul(t1, two, bb->b, ctx) == 0 ||
			    BN_mul(t2, r, bb->rsa->n, ctx) == 0 ||
			    BN_add(lower, t1, t2) == 0 ||
			    BN_div(lower, t1, lower, bb->si, ctx) == 0)
				goto fail;

			if (!BN_zero(t1))
				if (BN_add(lower, lower, BN_value_one()) == 0)
					goto fail;

			if (BN_cmp(lower, bb->m[0][i]->lower) < 0)
				/*
				if (BN_copy(lower, bb->m[0][i]->lower) == 0)
					goto fail;
				*/
				lower = bb->m[0][i]->lower;

			if (BN_mul(t1, three, bb->b, ctx) == 0 ||
			    BN_mul(t2, r, bb->rsa->n, ctx) == 0 ||
			    BN_add(upper, t1, t2) == 0 ||
			    BN_sub(upper, upper, BN_value_one()) == 0 ||
			    BN_div(upper, NULL, upper, bb->si, ctx) == 0)
				goto fail;

			if (BN_cmp(upper, bb->m[0][i]->upper) > 0)
				/*
				if (BN_copy(upper, bb->m[0][i]->upper) == 0)
					goto fail;
				*/
				upper = bb->m[0][i]->upper;

			if (bb_interval_update(bb, lower, upper) == 0)
				goto fail;

			if (BN_cmp(r, rmax) >= 0)
				break;

			if (BN_add(r, r, BN_value_one()) == 0)
				goto fail;
		}
	}

	bb_interval_final(bb);

	return 1;
fail:
	return 0;
}

int
main(void)
{
	RSA *rsa;
	BIGNUM *f4;
	uint8_t *enc;
	struct bb bb;

	if ((rsa = RSA_new()) == NULL ||
	    (f4 = BN_new()) == NULL ||

	    BN_set_word(f4, RSA_F4) == 0 ||
	    RSA_generate_key_ex(rsa, BITS, f4, NULL) == 0 ||

	    (enc = rsa_encrypt(rsa, (char *) data)) == NULL ||

	    bb_init(&bb, enc, rsa) == 0)
		err(1, NULL);
}
