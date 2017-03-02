#include <sys/types.h>

#include <err.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#define P	"800000000000000089e1855218a0e7dac38136ffafa72eda7"				\
		"859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"				\
		"2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"				\
		"ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"				\
		"b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"				\
		"1a584471bb1"

#define Q	"f4f47f05794b256174bba6e9b396a7707e563c5b"

#define G	"5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"				\
		"458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"				\
		"322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"				\
		"0f5b64c36b625a097f1651fe775323556fe00b3608c887892"				\
		"878480e99041be601a62166ca6894bdd41a7054ec89f756ba"				\
		"9fc95302291"

#define DATA	"For those that envy a MC it can be hazardous to your health\n"			\
		"So be friendly, a matter of life and death, just like a etch-a-sketch\n"

#define PUB_KEY	"84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"			\
		"abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"			\
		"e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"			\
		"1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"			\
		"bb283e6633451e535c45513b2d33c99ea17"

#define SIG_R	"548099063082341131477253921760299949438196259240"

#define SIG_S	"857042759984254168557880549501802188789837994940"

#define HASH	"0954edd5e0afe5542a4adf012611a91912a3ec16"

struct dsa {
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *g;
	BIGNUM *priv_key;
	BIGNUM *pub_key;
};

struct dsa_sig {
	BIGNUM *r;
	BIGNUM *s;
};

int
dsa_init(struct dsa *dsa)
{
	BN_CTX *ctx;

	if ((ctx = BN_CTX_new()) == NULL ||

	    (dsa->p = BN_new()) == NULL ||
	    (dsa->q = BN_new()) == NULL ||
	    (dsa->g = BN_new()) == NULL ||
	    (dsa->priv_key = BN_new()) == NULL ||
	    (dsa->pub_key = BN_new()) == NULL ||

	    BN_hex2bn(&dsa->p, P) == 0 ||
	    BN_hex2bn(&dsa->q, Q) == 0 ||
	    BN_hex2bn(&dsa->g, G) == 0)
		goto fail;

	do
		if (BN_rand_range(dsa->priv_key, dsa->q) == 0)
			goto fail;
	while (BN_is_zero(dsa->priv_key));

	if (BN_mod_exp(dsa->pub_key, dsa->g, dsa->priv_key, dsa->p, ctx) == 0)
		goto fail;

	return 1;
fail:
	return 0;
}

struct dsa_sig *
dsa_sig_create(struct dsa *dsa, uint8_t *buf, size_t len, BIGNUM **kp)
{
	BN_CTX *bnctx;
	struct dsa_sig *sig;
	BIGNUM *k, *kinv, *tmp;
	SHA1_CTX sha1ctx;
	uint8_t hash[SHA1_DIGEST_LENGTH];

	if ((bnctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(bnctx);

	if ((sig = malloc(sizeof(*sig))) == NULL ||
	    (sig->r = BN_new()) == NULL ||
	    (sig->s = BN_new()) == NULL ||

	    (k = BN_new()) == NULL ||
	    (kinv = BN_CTX_get(bnctx)) == NULL ||
	    (tmp = BN_CTX_get(bnctx)) == NULL)
		goto fail;

	do
		if (BN_rand_range(k, dsa->q) == 0)
			goto fail;
	while (BN_is_zero(k));

	if (BN_mod_exp(sig->r, dsa->g, k, dsa->p, bnctx) == 0 ||
	    BN_nnmod(sig->r, sig->r, dsa->q, bnctx) == 0)
		goto fail;

	SHA1Init(&sha1ctx);
	SHA1Update(&sha1ctx, buf, len);
	SHA1Final(hash, &sha1ctx);

	if (BN_bin2bn(hash, SHA1_DIGEST_LENGTH, sig->s) == NULL ||
	    BN_mod_mul(tmp, dsa->priv_key, sig->r, dsa->q, bnctx) == 0 ||
	    BN_mod_add(sig->s, sig->s, tmp, dsa->q, bnctx) == 0 ||
	    BN_mod_inverse(kinv, k, dsa->q, bnctx) == 0 ||
	    BN_mod_mul(sig->s, sig->s, kinv, dsa->q, bnctx) == 0)
		goto fail;

	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);

	if (kp != NULL)
		*kp = k;
	else
		free(k);

	return sig;
fail:
	return NULL;
}

int
dsa_sig_verify(struct dsa *dsa, uint8_t *buf, size_t len, struct dsa_sig *sig)
{
	BN_CTX *bnctx;
	BIGNUM *w, *u1, *u2, *v, *tmp;
	SHA1_CTX sha1ctx;
	uint8_t hash[SHA1_DIGEST_LENGTH];
	int cmp;

	if (BN_is_zero(sig->r) || BN_cmp(sig->r, dsa->q) >= 0 ||
	    BN_is_zero(sig->s) || BN_cmp(sig->s, dsa->q) >= 0 ||

	    (bnctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(bnctx);

	if ((w = BN_CTX_get(bnctx)) == NULL ||
	    (u1 = BN_CTX_get(bnctx)) == NULL ||
	    (u2 = BN_CTX_get(bnctx)) == NULL ||
	    (v = BN_CTX_get(bnctx)) == NULL ||
	    (tmp = BN_CTX_get(bnctx)) == NULL ||

	    BN_mod_inverse(w, sig->s, dsa->q, bnctx) == 0)
		goto fail;

	SHA1Init(&sha1ctx);
	SHA1Update(&sha1ctx, buf, len);
	SHA1Final(hash, &sha1ctx);

	if (BN_bin2bn(hash, SHA1_DIGEST_LENGTH, u1) == NULL ||
	    BN_mod_mul(u1, u1, w, dsa->q, bnctx) == 0 ||

	    BN_mod_mul(u2, sig->r, w, dsa->q, bnctx) == 0 ||

	    BN_mod_exp(v, dsa->g, u1, dsa->p, bnctx) == 0 ||    
	    BN_mod_exp(tmp, dsa->pub_key, u2, dsa->p, bnctx) == 0 ||    
	    BN_mod_mul(v, v, tmp, dsa->p, bnctx) == 0 ||
	    BN_nnmod(v, v, dsa->q, bnctx) == 0)
		goto fail;

	cmp = BN_cmp(v, sig->r);

	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);

	return cmp == 0;
fail:
	return 0;
}

void
dsa_sig_free(struct dsa_sig *sig)
{
	BN_free(sig->r);
	BN_free(sig->s);
	free(sig);
}

int
crack_dsa(BIGNUM *res, struct dsa *dsa, uint8_t *buf, size_t len, struct dsa_sig *sig, BIGNUM *k)
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
	BN_CTX *ctx;
	struct dsa dsa;
	struct dsa_sig sig;
	BIGNUM *k, *limit, *priv_key, *pub_key;
	size_t len;
	char *buf, hash[SHA1_DIGEST_STRING_LENGTH];

	if ((ctx = BN_CTX_new()) == NULL)
		err(1, NULL);
	BN_CTX_start(ctx);

	if (dsa_init(&dsa) == 0 ||
	    BN_hex2bn(&dsa.pub_key, PUB_KEY) == 0 ||

	    (sig.r = BN_CTX_get(ctx)) == NULL ||
	    (sig.s = BN_CTX_get(ctx)) == NULL ||
	    (k = BN_CTX_get(ctx)) == NULL ||
	    (limit = BN_CTX_get(ctx)) == NULL ||
	    (priv_key = BN_CTX_get(ctx)) == NULL ||
	    (pub_key = BN_CTX_get(ctx)) == NULL ||

	    BN_dec2bn(&sig.s, SIG_S) == 0 ||
	    BN_dec2bn(&sig.r, SIG_R) == 0 ||

	    BN_zero(k) == 0 ||
	    BN_hex2bn(&limit, "ffff") == 0)
		err(1, NULL);

	len = strlen(DATA);
	while (BN_cmp(k, limit) <= 0) {
		if (crack_dsa(priv_key, &dsa, DATA, len, &sig, k) == 0 ||
		    BN_mod_exp(pub_key, dsa.g, priv_key, dsa.p, ctx) == 0)
			err(1, NULL);

		if (BN_cmp(pub_key, dsa.pub_key) == 0)
			break;

		if (BN_add(k, k, BN_value_one()) == 0)
			err(1, NULL);
	}

	len = BN_num_bytes(priv_key);
	if ((buf = malloc(len)) == NULL ||
	    BN_bn2bin(priv_key, buf) == 0 ||
	    SHA1Data(buf, len, hash) == NULL)
		err(1, NULL);

	puts(strcmp(hash, HASH) == 0 ? buf : "failure");

	exit(0);
}
