#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/dsa.h>

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
main(void)
{
	return 0;
}
