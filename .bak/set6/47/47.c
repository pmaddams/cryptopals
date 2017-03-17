#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#define BITS 256

const char *data = "kick it, CC";

enum {
	PADDING_OK,
	PADDING_BAD,
	PADDING_ERR
};

struct bb {
	RSA *rsa;
	BIGNUM *b;
	BIGNUM *c;
	BIGNUM *s;
	BIGNUM *lower;
	BIGNUM *upper;
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
bb_init(struct bb *bb, RSA *rsa, uint8_t *enc)
{
	size_t rsa_len;
	BN_CTX *ctx;
	BIGNUM *two, *three;

	rsa_len = RSA_size(rsa);
	bb->rsa = rsa;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((bb->b = BN_new()) == NULL ||
	    (bb->c = BN_new()) == NULL ||
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
bb_generate_interval(struct bb *bb)
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

	    BN_mul(r, bb->lower, bb->s, ctx) == 0 ||
	    BN_mul(tmp, three, bb->b, ctx) == 0 ||
	    BN_sub(r, r, tmp) == 0 ||
	    BN_add(r, r, BN_value_one()) == 0 ||
	    BN_div(r, tmp, r, bb->rsa->n, ctx) == 0)
		goto fail;

	if (!BN_is_zero(tmp))
		if (BN_add(r, r, BN_value_one()) == 0)
			goto fail;

	if (BN_mul(rmax, bb->upper, bb->s, ctx) == 0 ||
	    BN_mul(tmp, two, bb->b, ctx) == 0 ||
	    BN_sub(rmax, rmax, tmp) == 0 ||
	    BN_div(rmax, NULL, rmax, bb->rsa->n, ctx) == 0)
		goto fail;

	if (BN_cmp(r, rmax) != 0)
		errx(1, "try again");

	if (BN_mul(newlower, two, bb->b, ctx) == 0 ||
	    BN_mul(tmp, r, bb->rsa->n, ctx) == 0 ||
	    BN_add(newlower, newlower, tmp) == 0 ||
	    BN_div(newlower, tmp, newlower, bb->s, ctx) == 0)
		goto fail;

	if (!BN_is_zero(tmp))
		if (BN_add(newlower, newlower, BN_value_one()) == 0)
			goto fail;

	if (BN_cmp(newlower, bb->lower) > 0)
		if (BN_copy(bb->lower, newlower) == 0)
			goto fail;

	if (BN_mul(newupper, three, bb->b, ctx) == 0 ||
	    BN_sub(newupper, newupper, BN_value_one()) == 0 ||
	    BN_mul(tmp, r, bb->rsa->n, ctx) == 0 ||
	    BN_add(newupper, newupper, tmp) == 0 ||
	    BN_div(newupper, NULL, newupper, bb->s, ctx) == 0)
		goto fail;

	if (BN_cmp(newupper, bb->upper) < 0)
		if (BN_copy(bb->upper, newupper) == 0)
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

	    BN_mul(r, bb->upper, bb->s, ctx) == 0 ||
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
		    BN_div(news, tmp, news, bb->upper, ctx) == 0)
			goto fail;

		if (!BN_is_zero(tmp))
			if (BN_add(news, news, BN_value_one()) == 0)
				goto fail;

		if (BN_mul(newslim, three, bb->b, ctx) == 0 ||
		    BN_mul(tmp, r, bb->rsa->n, ctx) == 0 ||
		    BN_add(newslim, newslim, tmp) == 0 ||
		    BN_div(newslim, tmp, newslim, bb->lower, ctx) == 0)
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

char *
crack_rsa(RSA *rsa, uint8_t *enc)
{
	struct bb bb;
	size_t i, len;
	char *res;

	if (bb_init(&bb, rsa, enc) == 0 ||
	    bb_find_first_s(&bb) == 0 ||
	    bb_generate_interval(&bb) == 0)
		goto fail;

	while (BN_cmp(bb.lower, bb.upper) != 0) {
		if (bb_find_next_s(&bb) == 0 ||
		    bb_generate_interval(&bb) == 0)
			goto fail;
	}

	if ((len = BN_num_bytes(bb.lower)) < 2 ||
	    (res = malloc(len)) == NULL ||
	    BN_bn2bin(bb.lower, res) == 0)
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

	    BN_set_word(f4, RSA_F4) == 0 ||
	    RSA_generate_key_ex(rsa, BITS, f4, NULL) == 0 ||

	    (enc = rsa_encrypt(rsa, (char *) data)) == NULL ||
	    (dec = crack_rsa(rsa, enc)) == NULL)
		err(1, NULL);

	puts(dec);

	exit(0);
}
