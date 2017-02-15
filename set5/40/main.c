#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "40.h"

#define VERBOSE

#define E	"3"
#define BITS	2048

struct rsa {
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *n;
	BIGNUM *e;
};

int
rsa_init(struct rsa *rsa)
{
	BN_CTX *ctx;

#ifdef VERBOSE
	fprintf(stderr, "initializing, please wait...");
#endif

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;

	memset(rsa, 0, sizeof(*rsa));

	if ((rsa->p = BN_new()) == NULL ||
	    (rsa->q = BN_new()) == NULL ||
	    (rsa->n = BN_new()) == NULL ||

	    BN_generate_prime_ex(rsa->p, BITS, 0, NULL, NULL, NULL) == 0 ||
	    BN_generate_prime_ex(rsa->q, BITS, 0, NULL, NULL, NULL) == 0 ||

	    BN_mul(rsa->n, rsa->p, rsa->q, ctx) == 0 ||

	    BN_dec2bn(&rsa->e, E) == 0)
		goto fail;

	BN_CTX_free(ctx);

#ifdef VERBOSE
	fprintf(stderr, "done.\n");
#endif

	return 1;
fail:
	return 0;
}

BIGNUM *
rsa_encrypt(struct rsa *rsa, uint8_t *buf, size_t len)
{
	BN_CTX *ctx;
	BIGNUM *in, *out;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((in = BN_CTX_get(ctx)) == NULL ||
	    (out = BN_new()) == NULL ||
	    BN_bin2bn(buf, len, in) == 0 ||
	    BN_mod_exp(out, in, rsa->e, rsa->n, ctx) == 0)
		goto fail;

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return out;
fail:
	return NULL;
}

BIGNUM *
crack_rsa(BIGNUM *c1, BIGNUM *n1, BIGNUM *c2, BIGNUM *n2, BIGNUM *c3, BIGNUM *n3)
{
	BN_CTX *ctx;
	BIGNUM *res, *tmp;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((res = BN_new()) == NULL ||
	    (tmp = BN_CTX_get(ctx)) == NULL ||

	    BN_zero(res) == 0 ||

	    BN_mul(tmp, n2, n3, ctx) == 0 ||
	    invmod(tmp, tmp, n1, ctx) == 0 ||
	    BN_mul(tmp, tmp, c1, ctx) == 0 ||
	    BN_mul(tmp, tmp, n2, ctx) == 0 ||
	    BN_mul(tmp, tmp, n3, ctx) == 0 ||
	    BN_add(res, res, tmp) == 0 ||

	    BN_mul(tmp, n1, n3, ctx) == 0 ||
	    invmod(tmp, tmp, n2, ctx) == 0 ||
	    BN_mul(tmp, tmp, c2, ctx) == 0 ||
	    BN_mul(tmp, tmp, n1, ctx) == 0 ||
	    BN_mul(tmp, tmp, n3, ctx) == 0 ||
	    BN_add(res, res, tmp) == 0 ||

	    BN_mul(tmp, n1, n2, ctx) == 0 ||
	    invmod(tmp, tmp, n3, ctx) == 0 ||
	    BN_mul(tmp, tmp, c3, ctx) == 0 ||
	    BN_mul(tmp, tmp, n1, ctx) == 0 ||
	    BN_mul(tmp, tmp, n2, ctx) == 0 ||
	    BN_add(res, res, tmp) == 0 ||

	    BN_mul(tmp, n1, n2, ctx) == 0 ||
	    BN_mul(tmp, tmp, n3, ctx) == 0 ||

	    BN_mod(res, res, tmp, ctx) == 0 ||

	    cubert(res, res, ctx) == 0)
		goto fail;

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return res;
fail:
	return NULL;
}

int
main(int argc, char **argv)
{
	struct rsa r1, r2, r3;
	char *in, *out;
	size_t inlen, outlen;
	BIGNUM *c1, *c2, *c3, *p;

	if (argc == 1) {
		fprintf(stderr, "usage: %s string ...\n", argv[0]);
		exit(0);
	}

	if (rsa_init(&r1) == 0 ||
	    rsa_init(&r2) == 0 ||
	    rsa_init(&r3) == 0 ||

	    (c1 = BN_new()) == NULL ||
	    (c2 = BN_new()) == NULL ||
	    (c3 = BN_new()) == NULL)
		err(1, NULL);

	while (argc > 1) {
		in = argv[1];
		inlen = strlen(in);

		if ((c1 = rsa_encrypt(&r1, in, inlen)) == NULL ||
		    (c2 = rsa_encrypt(&r2, in, inlen)) == NULL ||
		    (c3 = rsa_encrypt(&r3, in, inlen)) == NULL ||

		    (p = crack_rsa(c1, r1.n, c2, r2.n, c3, r3.n)) == NULL)
			err(1, NULL);

		outlen = BN_num_bytes(p);
		if ((out = malloc(outlen+1)) == NULL ||
		    BN_bn2bin(p, out) == 0)
			err(1, NULL);
		out[outlen] = '\0';

		puts(out);

		free(c1);
		free(c2);
		free(c3);
		free(p);
		free(out);

		argc--;
		argv++;
	}

	exit(0);
}
