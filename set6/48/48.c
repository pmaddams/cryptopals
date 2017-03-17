#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#define BITS 768

const char *data = "kick it, CC";

enum {
	PADDING_OK,
	PADDING_BAD,
	PADDING_ERR
};

struct interval {
	BIGNUM *upper;
	BIGNUM *lower;
	struct interval *next;
};

struct bb {
	RSA *rsa;
	BIGNUM *b;
	BIGNUM *c;
	BIGNUM *s;
	struct interval *m[2];
};

uint8_t *
rsa_encrypt(RSA *rsa, char *buf)
{
	uint8_t *res;

	if ((res = malloc(RSA_size(rsa))) == NULL ||
	    RSA_public_encrypt(strlen(buf)+1, buf, res, rsa, RSA_PKCS1_PADDING) == -1)
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
	if (BN_bn2bin(c, t1+rsa_len-BN_num_bytes(c)) == 0 ||
	    RSA_private_decrypt(rsa_len, t1, t2, rsa, RSA_NO_PADDING) == -1)
		goto fail;

	if (memcmp(t2, "\x00\x02", 2) == 0)
		return PADDING_OK;
	else
		return PADDING_BAD;
fail:
	return PADDING_ERR;
}

int
bb_interval_update(struct bb *bb, BIGNUM *lower, BIGNUM *upper)
{
	struct interval *m, *p;

	if ((m = malloc(sizeof(*m))) == NULL ||
	    (m->lower = BN_new()) == NULL ||
	    (m->upper = BN_new()) == NULL ||

	    BN_copy(m->lower, lower) == 0 ||
	    BN_copy(m->upper, upper) == 0)
		goto fail;

	m->next = NULL;

	if ((p = bb->m[1]) == NULL)
		bb->m[1] = m;
	else {
		while (p->next != NULL)
			p = p->next;
		p->next = m;
	}

	return 1;
fail:
	return 0;
}

void
bb_interval_final(struct bb *bb)
{
	struct interval *p, *next;

	for (p = bb->m[0]; p != NULL; p = next) {
		next = p->next;
		BN_free(p->lower);
		BN_free(p->upper);
		free(p);
	}

	bb->m[0] = bb->m[1];
	bb->m[1] = NULL;
}

int
bb_init(struct bb *bb, RSA *rsa, uint8_t *enc)
{
	size_t rsa_len;
	BN_CTX *ctx;
	BIGNUM *two, *three, *lower, *upper;

	rsa_len = RSA_size(rsa);
	bb->rsa = rsa;
	bb->m[0] = bb->m[1] = NULL;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((bb->b = BN_new()) == NULL ||
	    (bb->c = BN_new()) == NULL ||
	    (bb->s = BN_new()) == NULL ||

	    (two = BN_CTX_get(ctx)) == NULL ||
	    (three = BN_CTX_get(ctx)) == NULL ||
	    (lower = BN_CTX_get(ctx)) == NULL ||
	    (upper = BN_CTX_get(ctx)) == NULL ||

	    BN_set_word(two, 2) == 0 ||
	    BN_set_word(three, 3) == 0 ||

	    BN_set_word(bb->b, 8*(rsa_len-2)) == 0 ||
	    BN_exp(bb->b, two, bb->b, ctx) == 0 ||

	    BN_bin2bn(enc, rsa_len, bb->c) == NULL ||

	    BN_mul(lower, two, bb->b, ctx) == 0 ||
	    BN_mul(upper, three, bb->b, ctx) == 0 ||
	    BN_sub(upper, upper, BN_value_one()) == 0 ||

	    bb_interval_update(bb, lower, upper) == 0)
		goto fail;
	bb_interval_final(bb);

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return 1;
fail:
	return 0;
}

int
bb_find_first_s(struct bb *bb)
{
	BN_CTX *ctx;
	BIGNUM *cprime, *tmp;
	int padding;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((cprime = BN_CTX_get(ctx)) == NULL ||
	    (tmp = BN_CTX_get(ctx)) == NULL ||

	    BN_set_word(tmp, 3) == 0 ||
	    BN_mul(tmp, tmp, bb->b, ctx) == 0 ||
	    BN_div(bb->s, tmp, bb->rsa->n, tmp, ctx) == 0)
		goto fail;

	for (;;) {
		if (BN_mod_exp(cprime, bb->s, bb->rsa->e, bb->rsa->n, ctx) == 0 ||
		    BN_mod_mul(cprime, cprime, bb->c, bb->rsa->n, ctx) == 0)
			goto fail;

		if ((padding = rsa_check_padding(bb->rsa, cprime)) == PADDING_ERR)
			goto fail;
		else if (padding == PADDING_OK)
			break;

		if (BN_add(bb->s, bb->s, BN_value_one()) == 0)
			goto fail;
	}

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return 1;
fail:
	return 0;
}

int
bb_generate_intervals_each(struct bb *bb, struct interval *m)
{
	BN_CTX *ctx;
	BIGNUM *r, *rmax, *tmp, *two, *three,
	    *newlower, *newupper;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((r = BN_CTX_get(ctx)) == NULL ||
	    (rmax = BN_CTX_get(ctx)) == NULL ||
	    (tmp = BN_CTX_get(ctx)) == NULL ||
	    (two = BN_CTX_get(ctx)) == NULL ||
	    (three = BN_CTX_get(ctx)) == NULL ||
	    (newlower = BN_CTX_get(ctx)) == NULL ||
	    (newupper = BN_CTX_get(ctx)) == NULL ||

	    BN_set_word(two, 2) == 0 ||
	    BN_set_word(three, 3) == 0 ||

	    BN_mul(r, m->lower, bb->s, ctx) == 0 ||
	    BN_mul(tmp, three, bb->b, ctx) == 0 ||
	    BN_sub(r, r, tmp) == 0 ||
	    BN_add(r, r, BN_value_one()) == 0 ||
	    BN_div(r, tmp, r, bb->rsa->n, ctx) == 0)
		goto fail;

	if (!BN_is_zero(tmp))
		if (BN_add(r, r, BN_value_one()) == 0)
			goto fail;

	if (BN_mul(rmax, m->upper, bb->s, ctx) == 0 ||
	    BN_mul(tmp, two, bb->b, ctx) == 0 ||
	    BN_sub(rmax, rmax, tmp) == 0 ||
	    BN_div(rmax, NULL, rmax, bb->rsa->n, ctx) == 0)
		goto fail;

	while (BN_cmp(r, rmax) <= 0) {
		if (BN_mul(newlower, two, bb->b, ctx) == 0 ||
		    BN_mul(tmp, r, bb->rsa->n, ctx) == 0 ||
		    BN_add(newlower, newlower, tmp) == 0 ||
		    BN_div(newlower, tmp, newlower, bb->s, ctx) == 0)
			goto fail;

		if (!BN_is_zero(tmp))
			if (BN_add(newlower, newlower, BN_value_one()) == 0)
				goto fail;

		if (BN_cmp(m->lower, newlower) > 0)
			if (BN_copy(newlower, m->lower) == 0)
				goto fail;

		if (BN_mul(newupper, three, bb->b, ctx) == 0 ||
		    BN_sub(newupper, newupper, BN_value_one()) == 0 ||
		    BN_mul(tmp, r, bb->rsa->n, ctx) == 0 ||
		    BN_add(newupper, newupper, tmp) == 0 ||
		    BN_div(newupper, NULL, newupper, bb->s, ctx) == 0)
			goto fail;

		if (BN_cmp(m->upper, newupper) < 0)
			if (BN_copy(newupper, m->upper) == 0)
				goto fail;

		if (bb_interval_update(bb, newlower, newupper) == 0)
			goto fail;

		if (BN_add(r, r, BN_value_one()) == 0)
			goto fail;
	}

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return 1;
fail:
	return 0;
}

int
bb_generate_intervals(struct bb *bb)
{
	struct interval *p;

	for (p = bb->m[0]; p != NULL; p = p->next)
		if (bb_generate_intervals_each(bb, p) == 0)
			goto fail;

	bb_interval_final(bb);

	return 1;
fail:
	return 0;
}

int
bb_find_next_s_many(struct bb *bb)
{
	BN_CTX *ctx;
	BIGNUM *cprime;
	int padding;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((cprime = BN_CTX_get(ctx)) == NULL ||

	    BN_add(bb->s, bb->s, BN_value_one()) == 0)
		goto fail;

	for (;;) {
		if (BN_mod_exp(cprime, bb->s, bb->rsa->e, bb->rsa->n, ctx) == 0 ||
		    BN_mod_mul(cprime, cprime, bb->c, bb->rsa->n, ctx) == 0)
			goto fail;

		if ((padding = rsa_check_padding(bb->rsa, cprime)) == PADDING_ERR)
			goto fail;
		else if (padding == PADDING_OK)
			break;

		if (BN_add(bb->s, bb->s, BN_value_one()) == 0)
			goto fail;
	}

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return 1;
fail:
	return 0;
}

int
bb_find_next_s_one(struct bb *bb)
{
	BN_CTX *ctx;
	BIGNUM *r, *news, *newslim, *cprime, *tmp, *two, *three;
	int padding;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((r = BN_CTX_get(ctx)) == NULL ||
	    (news = BN_CTX_get(ctx)) == NULL ||
	    (newslim = BN_CTX_get(ctx)) == NULL ||
	    (cprime = BN_CTX_get(ctx)) == NULL ||
	    (tmp = BN_CTX_get(ctx)) == NULL ||
	    (two = BN_CTX_get(ctx)) == NULL ||
	    (three = BN_CTX_get(ctx)) == NULL ||

	    BN_set_word(two, 2) == 0 ||
	    BN_set_word(three, 3) == 0 ||

	    BN_mul(r, bb->m[0]->upper, bb->s, ctx) == 0 ||
	    BN_mul(tmp, two, bb->b, ctx) == 0 ||
	    BN_sub(r, r, tmp) == 0 ||
	    BN_mul(r, r, two, ctx) == 0 ||
	    BN_div(r, tmp, r, bb->rsa->n, ctx) == 0)
		goto fail;

	if (!BN_is_zero(tmp))
		if (BN_add(r, r, BN_value_one()) == 0)
			goto fail;

	for (;;) {
		if (BN_mul(news, two, bb->b, ctx) == 0 ||
		    BN_mul(tmp, r, bb->rsa->n, ctx) == 0 ||
		    BN_add(news, news, tmp) == 0 ||
		    BN_div(news, tmp, news, bb->m[0]->upper, ctx) == 0)
			goto fail;

		if (!BN_is_zero(tmp))
			if (BN_add(news, news, BN_value_one()) == 0)
				goto fail;

		if (BN_mul(newslim, three, bb->b, ctx) == 0 ||
		    BN_mul(tmp, r, bb->rsa->n, ctx) == 0 ||
		    BN_add(newslim, newslim, tmp) == 0 ||
		    BN_div(newslim, tmp, newslim, bb->m[0]->lower, ctx) == 0)
			goto fail;

		if (!BN_is_zero(tmp))
			if (BN_add(newslim, newslim, BN_value_one()) == 0)
				goto fail;

		while (BN_cmp(news, newslim) != 0) {
			if (BN_mod_exp(cprime, news, bb->rsa->e, bb->rsa->n, ctx) == 0 ||
			    BN_mod_mul(cprime, cprime, bb->c, bb->rsa->n, ctx) == 0)
				goto fail;

			if ((padding = rsa_check_padding(bb->rsa, cprime)) == PADDING_ERR)
				goto fail;
			else if (padding == PADDING_OK)
				goto done;

			if (BN_add(news, news, BN_value_one()) == 0)
				goto fail;
		}

		if (BN_add(r, r, BN_value_one()) == 0)
			goto fail;
	}
done:
	if (BN_copy(bb->s, news) == 0)
		goto fail;

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return 1;
fail:
	return 0;
}

int
bb_find_next_s(struct bb *bb)
{
	if (bb->m[0]->next != NULL)
		return bb_find_next_s_many(bb);
	else
		return bb_find_next_s_one(bb);
}

char *
crack_rsa(RSA *rsa, uint8_t *enc)
{
	struct bb bb;
	size_t i, len;
	char *res;

	if (bb_init(&bb, rsa, enc) == 0 ||
	    bb_find_first_s(&bb) == 0 ||
	    bb_generate_intervals(&bb) == 0)
		goto fail;

	while (BN_cmp(bb.m[0]->lower, bb.m[0]->upper) != 0) {
		if (bb_find_next_s(&bb) == 0 ||
		    bb_generate_intervals(&bb) == 0)
			goto fail;
	}

	if ((len = BN_num_bytes(bb.m[0]->lower)) < 2 ||
	    (res = malloc(len)) == NULL ||
	    BN_bn2bin(bb.m[0]->lower, res) == 0)
		goto fail;

	for (i = len-2; i > 0; i--)
		if (res[i] == '\0')
			break;

	len -= i;
	memmove(res, res+i+1, len);
	res[len] = '\0';

	return res;
fail:
	return NULL;
}

int
main(void)
{
	RSA *rsa;
	BIGNUM *f4;
	uint8_t *enc, *dec;

	if ((rsa = RSA_new()) == NULL ||
	    (f4 = BN_new()) == NULL ||

	    BN_set_word(f4, 3) == 0 ||
	    RSA_generate_key_ex(rsa, BITS, f4, NULL) == 0 ||

	    (enc = rsa_encrypt(rsa, (char *) data)) == NULL ||
	    (dec = crack_rsa(rsa, enc)) == NULL)
		err(1, NULL);

	puts(dec);

	exit(0);
}
