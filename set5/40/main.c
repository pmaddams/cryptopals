#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "40.h"

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

BIGNUM *
crack_rsa()
{

}

int
main(void)
{
	return 0;
}
