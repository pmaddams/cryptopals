#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#define BITS 256

struct interval {
	BIGNUM *lower;
	BIGNUM *upper;
};

struct bb {
	BIGNUM *n;
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
bb_init(struct bb *bb, uint8_t *enc, BIGNUM *n)
{
	int rsa_len;
	BN_CTX *ctx;
	BIGNUM *tmp;

	rsa_len = BN_num_bytes(n);

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((bb->n = BN_new()) == NULL ||
	    (bb->b = BN_new()) == NULL ||
	    (bb->c0 = BN_new()) == NULL ||
	    (bb->ci = BN_new()) == NULL ||
	    (bb->s0 = BN_new()) == NULL ||
	    (bb->si = BN_new()) == NULL ||

	    (tmp = BN_CTX_get(ctx)) == NULL ||

	    BN_copy(bb->n, n) == 0 ||

	    BN_set_word(bb->b, 8*(rsa_len-2)) == 0 ||
	    BN_set_word(tmp, 2) == 0 ||
	    BN_exp(bb->b, tmp, bb->b, ctx) == 0 ||

	    BN_bin2bn(enc, rsa_len, bb->c0) == NULL ||

	    BN_one(bb->s0) == 0)
		goto fail;

	bb->m = NULL;
	bb->i = 1;

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return 1;
fail:
	return 0;
}

int
check_padding(RSA *rsa, struct bb *bb)
{
	static uint8_t *t1, *t2;
	size_t rsa_size;

	if (t1 == NULL || t2 == NULL) {
		rsa_size = RSA_size(rsa);
		if ((t1 = malloc(rsa_size)) == NULL ||
		    (t2 = malloc(rsa_size)) == NULL)
			goto fail;
	}

	if (BN_bn2bin(bb->ci, t1) == 0)
		goto fail;

	return RSA_private_decrypt(rsa_size, t1, t2, rsa, RSA_PKCS1_PADDING) != -1;
fail:
	return -1;
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

	    bb_init(&bb, enc, rsa->n) == 0)
		err(1, NULL);
}
