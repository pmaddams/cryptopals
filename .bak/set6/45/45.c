#include <sys/types.h>

#include <err.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/dsa.h>

#define BITS 2048

DSA_SIG *
magic_sig(DSA *dsa)
{
	BN_CTX *ctx;
	DSA_SIG *sig;
	BIGNUM *z;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((sig = DSA_SIG_new()) == NULL ||
	    (sig->r = BN_new()) == NULL ||
	    (sig->s = BN_new()) == NULL ||

	    (z = BN_CTX_get(ctx)) == NULL)
		goto fail;

	do
		if (BN_rand_range(z, dsa->q) == 0)
			goto fail;
	while (BN_is_zero(z));

	if (BN_mod_exp(sig->r, dsa->pub_key, z, dsa->p, ctx) == 0 ||
	    BN_nnmod(sig->r, sig->r, dsa->q, ctx) == 0 ||

	    BN_mod_inverse(z, z, dsa->q, ctx) == 0 ||
	    BN_mod_mul(sig->s, sig->r, z, dsa->q, ctx) == 0)
		goto fail;

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return sig;
fail:
	return NULL;
}

int
main(int argc, char **argv)
{
	DSA *dsa;
	DSA_SIG *sig;
	char *s;
	SHA2_CTX ctx;
	uint8_t hash[SHA256_DIGEST_LENGTH];

	if (argc == 1) {
		fprintf(stderr, "usage: %s string ...\n", argv[0]);
		exit(1);
	}

	if ((dsa = DSA_new()) == NULL ||

	    DSA_generate_parameters_ex(dsa, BITS, NULL, 0, NULL, NULL, NULL) == 0 ||
	    DSA_generate_key(dsa) == 0 ||

	    BN_copy(dsa->g, dsa->p) == 0 ||
	    BN_add(dsa->g, dsa->g, BN_value_one()) == 0 ||

	    (sig = magic_sig(dsa)) == NULL)
		err(1, NULL);
 
	while (argc > 1) {
		s = argv[1];
	
		SHA256Init(&ctx);
		SHA256Update(&ctx, s, strlen(s));
		SHA256Final(hash, &ctx);
	
		puts(DSA_do_verify(hash, SHA256_DIGEST_LENGTH, sig, dsa) ? "success" : "failure");
	
		argc--;
		argv++;
	}

	exit(0);
}
