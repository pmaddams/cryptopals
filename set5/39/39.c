#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#define VERBOSE

#define E	"3"
#define BITS	2048

#define DECRYPT	0
#define ENCRYPT	1

struct rsa {
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *d;
};

BIGNUM *
invmod(BIGNUM *a, BIGNUM *modulus)
{
	BIGNUM *res, *remainder, *quotient, *x1, *x2, *t1, *t2;
	BN_CTX *ctx;

	if (BN_is_zero(a) || BN_is_zero(modulus))
		goto fail;
	if (BN_is_one(a) || BN_is_one(modulus)) {
		res = BN_dup(BN_value_one());
		goto done;
	}

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((res = BN_dup(a)) == NULL ||
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
	    BN_mod(res, x1, modulus, ctx) == 0)
		goto fail;

	if (BN_is_negative(res))
		BN_add(res, modulus, res);

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

char *
rsa_crypt(struct rsa *rsa, uint8_t *inbuf, size_t inlen, size_t *outlenp, int enc)
{
	BN_CTX *ctx;
	BIGNUM *in, *out;
	size_t outlen;
	char *outbuf;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((in = BN_CTX_get(ctx)) == NULL ||
	    (out = BN_CTX_get(ctx)) == NULL ||
	    BN_bin2bn(inbuf, inlen, in) == 0 ||
	    BN_mod_exp(out, in, enc ? rsa->e : rsa->d, rsa->n, ctx) == 0)
		goto fail;

	outlen = BN_num_bytes(out);
	if ((outbuf = malloc(outlen+1)) == NULL ||
	    BN_bn2bin(out, outbuf) == 0)
		goto fail;

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	outbuf[outlen] = '\0';
	if (outlenp != NULL)
		*outlenp = outlen;

	return outbuf;
fail:
	return NULL;
}

int
main(int argc, char **argv)
{
	struct rsa rsa;
	char *s, *enc, *dec;
	size_t enclen;

	if (argc == 1) {
		fprintf(stderr, "usage: %s string ...\n", argv[0]);
		exit(1);
	}

	if (rsa_init(&rsa) == 0)
		err(1, NULL);

	while (argc > 1) {
		s = argv[1];
		if ((enc = rsa_crypt(&rsa, s, strlen(s), &enclen, ENCRYPT)) == NULL ||
		    (dec = rsa_crypt(&rsa, enc, enclen, NULL, DECRYPT)) == NULL)
			err(1, NULL);

		puts(dec);

		free(enc);
		free(dec);
		argc--;
		argv++;
	}

	exit(0);
}
