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

	cprime = BN_CTX_get(ctx);
	tmp = BN_CTX_get(ctx);

	BN_set_word(tmp, 3);
	BN_mul(tmp, tmp, bb->b, ctx);
	BN_div(bb->s, tmp, bb->rsa->n, tmp, ctx);

	for (;;) {
		BN_mod_exp(cprime, bb->s, bb->rsa->e, bb->rsa->n, ctx);
		BN_mod_mul(cprime, cprime, bb->c, bb->rsa->n, ctx);

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

	ctx = BN_CTX_new();
	BN_CTX_start(ctx);

	r = BN_CTX_get(ctx);
	rmax = BN_CTX_get(ctx);
	tmp = BN_CTX_get(ctx);
	two = BN_CTX_get(ctx);
	three = BN_CTX_get(ctx);
	newlower = BN_CTX_get(ctx);
	newupper = BN_CTX_get(ctx);

	BN_set_word(two, 2);
	BN_set_word(three, 3);

	BN_mul(r, bb->lower, bb->s, ctx);
	BN_mul(tmp, three, bb->b, ctx);
	BN_sub(r, r, tmp);
	BN_add(r, r, BN_value_one());
	BN_div(r, tmp, r, bb->rsa->n, ctx);
	if (!BN_is_zero(tmp))
		BN_add(r, r, BN_value_one());

	BN_mul(rmax, bb->upper, bb->s, ctx);
	BN_mul(tmp, two, bb->b, ctx);
	BN_sub(rmax, rmax, tmp);
	BN_div(rmax, NULL, rmax, bb->rsa->n, ctx);

	if (BN_cmp(r, rmax) != 0)
		errx(1, "multiple intervals");

	BN_mul(newlower, two, bb->b, ctx);
	BN_mul(tmp, r, bb->rsa->n, ctx);
	BN_add(newlower, newlower, tmp);
	BN_div(newlower, tmp, newlower, bb->s, ctx);
	if (!BN_is_zero(tmp))
		BN_add(newlower, newlower, BN_value_one());

	if (BN_cmp(newlower, bb->lower) > 0)
		BN_copy(bb->lower, newlower);

	BN_mul(newupper, three, bb->b, ctx);
	BN_sub(newupper, newupper, BN_value_one());
	BN_mul(tmp, r, bb->rsa->n, ctx);
	BN_add(newupper, newupper, tmp);
	BN_div(newupper, NULL, newupper, bb->s, ctx);

	if (BN_cmp(newupper, bb->upper) < 0)
		BN_copy(bb->upper, newupper);

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

	ctx = BN_CTX_new();
	BN_CTX_start(ctx);

	r = BN_CTX_get(ctx);
	news = BN_CTX_get(ctx);
	newslim = BN_CTX_get(ctx);
	cprime = BN_CTX_get(ctx);
	tmp = BN_CTX_get(ctx);
	two = BN_CTX_get(ctx);
	three = BN_CTX_get(ctx);

	BN_set_word(two, 2);
	BN_set_word(three, 3);

	BN_mul(r, bb->upper, bb->s, ctx);
	BN_mul(tmp, two, bb->b, ctx);
	BN_sub(r, r, tmp);
	BN_mul(r, r, two, ctx);
	BN_div(r, tmp, r, bb->rsa->n, ctx);
	if (!BN_is_zero(tmp))
		BN_add(r, r, BN_value_one());

	for (;;) {
		BN_mul(news, two, bb->b, ctx);
		BN_mul(tmp, r, bb->rsa->n, ctx);
		BN_add(news, news, tmp);
		BN_div(news, tmp, news, bb->upper, ctx);
		if (!BN_is_zero(tmp))
			BN_add(news, news, BN_value_one());

		BN_mul(newslim, three, bb->b, ctx);
		BN_mul(tmp, r, bb->rsa->n, ctx);
		BN_add(newslim, newslim, tmp);
		BN_div(newslim, tmp, newslim, bb->lower, ctx);
		if (!BN_is_zero(tmp))
			BN_add(newslim, newslim, BN_value_one());

		while (BN_cmp(news, newslim) != 0) {
			BN_mod_exp(cprime, news, bb->rsa->e, bb->rsa->n, ctx);
			BN_mod_mul(cprime, cprime, bb->c, bb->rsa->n, ctx);

			if ((padding = rsa_check_padding(bb->rsa, cprime)) == PADDING_ERR)
				goto fail;
			else if (padding == PADDING_OK)
				goto done;

			if (BN_add(news, news, BN_value_one()) == 0)
				goto fail;
		}

		BN_add(r, r, BN_value_one());
	}
done:
	BN_copy(bb->s, news);

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
	char *res, *p;

	bb_init(&bb, rsa, enc);
	bb_find_first_s(&bb);
	bb_generate_interval(&bb);

	while (BN_cmp(bb.lower, bb.upper) != 0) {
		bb_find_next_s(&bb);
		bb_generate_interval(&bb);
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
	BIGNUM *three;
	uint8_t *enc, *dec;

	rsa = RSA_new();
	three = BN_new();
	BN_set_word(three, 3);
	RSA_generate_key_ex(rsa, BITS, three, NULL);

	enc = rsa_encrypt(rsa, (char *) data);
	dec = crack_rsa(rsa, enc);

	puts(dec);

	exit(0);
}
