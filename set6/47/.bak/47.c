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
	struct interval *m;
	size_t m_len;
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
	size_t rsa_len;

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
bb_init(struct bb *bb, uint8_t *enc, RSA *rsa)
{
	size_t rsa_len;
	BN_CTX *ctx;
	BIGNUM *tmp;

	rsa_len = RSA_size(rsa);
	bb->rsa = rsa;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((bb->b = BN_new()) == NULL ||
	    (bb->c0 = BN_new()) == NULL ||
	    (bb->ci = BN_new()) == NULL ||
	    (bb->s0 = BN_new()) == NULL ||
	    (bb->si = BN_new()) == NULL ||

	    (tmp = BN_CTX_get(ctx)) == NULL ||

	    BN_set_word(bb->b, 8*(rsa_len-2)) == 0 ||
	    BN_set_word(tmp, 2) == 0 ||
	    BN_exp(bb->b, tmp, bb->b, ctx) == 0 ||

	    BN_bin2bn(enc, rsa_len, bb->c0) == NULL ||

	    BN_one(bb->s0) == 0)
		goto fail;

	bb->m = NULL;
	bb->m_len = 0;
	bb->i = 1;

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return 1;
fail:
	return 0;
}

int
bb_append_interval(struct bb *bb)
{
	struct interval *newp;
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
