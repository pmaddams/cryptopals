#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "40.h"

int
crack_rsa(BIGNUM *res, BIGNUM *c1, BIGNUM *n1, BIGNUM *c2, BIGNUM *n2, BIGNUM *c3, BIGNUM *n3)
{
	BN_CTX *ctx;
	BIGNUM *tmp, *out;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((tmp = BN_CTX_get(ctx)) == NULL ||
	    (out = BN_CTX_get(ctx)) == NULL ||

	    BN_zero(out) == 0 ||

	    BN_mul(tmp, n2, n3, ctx) == 0 ||
	    invmod(tmp, tmp, n1, ctx) == 0 ||
	    BN_mul(tmp, tmp, c1, ctx) == 0 ||
	    BN_mul(tmp, tmp, n2, ctx) == 0 ||
	    BN_mul(tmp, tmp, n3, ctx) == 0 ||
	    BN_add(out, out, tmp) == 0 ||

	    BN_mul(tmp, n1, n3, ctx) == 0 ||
	    invmod(tmp, tmp, n2, ctx) == 0 ||
	    BN_mul(tmp, tmp, c2, ctx) == 0 ||
	    BN_mul(tmp, tmp, n1, ctx) == 0 ||
	    BN_mul(tmp, tmp, n3, ctx) == 0 ||
	    BN_add(out, out, tmp) == 0 ||

	    BN_mul(tmp, n1, n2, ctx) == 0 ||
	    invmod(tmp, tmp, n3, ctx) == 0 ||
	    BN_mul(tmp, tmp, c3, ctx) == 0 ||
	    BN_mul(tmp, tmp, n1, ctx) == 0 ||
	    BN_mul(tmp, tmp, n2, ctx) == 0 ||
	    BN_add(out, out, tmp) == 0 ||

	    BN_mul(tmp, n1, n2, ctx) == 0 ||
	    BN_mul(tmp, tmp, n3, ctx) == 0 ||

	    BN_mod(out, out, tmp, ctx) == 0 ||

	    cubert(out, out, ctx) == 0 ||

	    BN_copy(res, out) == NULL)
		goto fail;

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return 1;
fail:
	return 0;
}

int
main(int argc, char **argv)
{
	RSA *r1, *r2, *r3;
	BIGNUM *e, *c1, *c2, *c3, *p;
	ssize_t rsa_size;
	char *s, *enc, *dec;

	if (argc == 1) {
		fprintf(stderr, "usage: %s string ...\n", argv[0]);
		exit(1);
	}

	if ((r1 = RSA_new()) == NULL ||
	    (r2 = RSA_new()) == NULL ||
	    (r3 = RSA_new()) == NULL ||

	    (e = BN_new()) == NULL ||
	    (c1 = BN_new()) == NULL ||
	    (c2 = BN_new()) == NULL ||
	    (c3 = BN_new()) == NULL ||
	    (p = BN_new()) == NULL ||

	    BN_dec2bn(&e, E) == 0 ||

	    RSA_generate_key_ex(r1, BITS, e, NULL) == 0 ||
	    RSA_generate_key_ex(r2, BITS, e, NULL) == 0 ||
	    RSA_generate_key_ex(r3, BITS, e, NULL) == 0)
		err(1, NULL);

	BN_free(e);

	rsa_size = RSA_size(r1);
	if ((enc = malloc(rsa_size)) == NULL ||
	    (dec = malloc(rsa_size)) == NULL)
		err(1, NULL);

	while (argc > 1) {
		s = argv[1];

		if (RSA_public_encrypt(rsa_size, s, enc, r1, RSA_NO_PADDING) == 0 ||
		    BN_bin2bn(enc, rsa_size, c1) == NULL ||

		    RSA_public_encrypt(rsa_size, s, enc, r2, RSA_NO_PADDING) == 0 ||
		    BN_bin2bn(enc, rsa_size, c2) == NULL ||

		    RSA_public_encrypt(rsa_size, s, enc, r3, RSA_NO_PADDING) == 0 ||
		    BN_bin2bn(enc, rsa_size, c3) == NULL ||

		    crack_rsa(p, c1, r1->n, c2, r2->n, c3, r3->n) == 0 ||

		    BN_bn2bin(p, dec) == 0)
			err(1, NULL);

		puts(dec);

		argc--;
		argv++;
	}

	exit(0);
}
