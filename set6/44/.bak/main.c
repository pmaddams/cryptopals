#include <sys/types.h>

#include <err.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/dsa.h>

#include "44.h"

int
crack_dsa(BIGNUM *res, DSA *dsa, uint8_t *buf, size_t len, DSA_SIG *sig, BIGNUM *k)
{
	BN_CTX *bnctx;
	BIGNUM *tmp;
	SHA1_CTX sha1ctx;
	uint8_t hash[SHA1_DIGEST_LENGTH];

	if ((bnctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(bnctx);

	if ((tmp = BN_CTX_get(bnctx)) == NULL ||

	    BN_mod_mul(res, sig->s, k, dsa->q, bnctx) == 0)
		goto fail;

	SHA1Init(&sha1ctx);
	SHA1Update(&sha1ctx, buf, len);
	SHA1Final(hash, &sha1ctx);

	if (BN_bin2bn(hash, SHA1_DIGEST_LENGTH, tmp) == NULL ||
	    BN_mod_sub(res, res, tmp, dsa->q, bnctx) == 0 ||

	    BN_mod_inverse(tmp, sig->r, dsa->q, bnctx) == 0 ||
	    BN_mod_mul(res, res, tmp, dsa->q, bnctx) == 0)
		goto fail;

	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);

	return 1;
fail:
	return 0;
}

int
main(void)
{
	FILE *fp;
	struct data data;

	if ((fp = fopen(FILENAME, "r")) == NULL ||
	    load_data(&data, fp) == 0)
		err(1, NULL);

	exit(0);
}
