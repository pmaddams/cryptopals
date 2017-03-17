#include <sys/types.h>

#include <err.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#define P	"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"	\
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"	\
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"	\
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"	\
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"	\
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"	\
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"	\
		"fffffffffffff"
#define G	"2"

#define BITS	2048

#define KEYSIZE	16

struct dh {
	BIGNUM *p;
	BIGNUM *g;
	BIGNUM *pub_key;
	BIGNUM *priv_key;
};

struct party {
	struct dh *dh;
	uint8_t enc_key[KEYSIZE];
	uint8_t mac_key[KEYSIZE];
};

int
dh_init(struct party *party)
{
	BN_CTX *ctx;
	struct dh *dh;

	if ((ctx = BN_CTX_new()) == NULL ||

	    (dh = malloc(sizeof(*dh))) == NULL ||
	    (dh->p = BN_new()) == NULL ||
	    (dh->g = BN_new()) == NULL ||
	    (dh->pub_key = BN_new()) == NULL ||
	    (dh->priv_key = BN_new()) == NULL ||

	    BN_hex2bn(&dh->p, P) == 0 ||
	    BN_hex2bn(&dh->g, G) == 0 ||
	    BN_rand(dh->priv_key, BITS, 0, 0) == 0 ||
	    BN_mod_exp(dh->pub_key, dh->g, dh->priv_key, dh->p, ctx) == 0)
		goto fail;

	party->dh = dh;

	BN_CTX_free(ctx);
	return 1;
fail:
	return 0;
}

int
dh_exchange(struct party *p1, struct party *p2)
{
	BN_CTX *bnctx;
	BIGNUM *secret;
	size_t len;
	uint8_t *buf, hash[SHA256_DIGEST_LENGTH];
	SHA2_CTX sha2ctx;

	if ((bnctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(bnctx);

	if ((secret = BN_CTX_get(bnctx)) == NULL ||
	    BN_mod_exp(secret, p2->dh->pub_key, p1->dh->priv_key, p1->dh->p, bnctx) == 0)
		goto fail;

	len = BN_num_bytes(secret);
	if ((buf = malloc(len)) == NULL ||
	    BN_bn2bin(secret, buf) == 0)
		goto fail;

	SHA256Init(&sha2ctx);
	SHA256Update(&sha2ctx, buf, len);
	SHA256Final(hash, &sha2ctx);

	memcpy(p1->enc_key, hash, KEYSIZE);
	memcpy(p1->mac_key, hash+KEYSIZE, KEYSIZE);

	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);

	return 1;
fail:
	return 0;
}

int
dh_verify(struct party *p1, struct party *p2, char *message)
{
	SHA2_CTX ctx;
	uint8_t mac1[SHA256_DIGEST_LENGTH],
	    mac2[SHA256_DIGEST_LENGTH];

	SHA256Init(&ctx);
	SHA256Update(&ctx, p1->mac_key, KEYSIZE);
	SHA256Update(&ctx, message, strlen(message));
	SHA256Final(mac1, &ctx);

	SHA256Init(&ctx);
	SHA256Update(&ctx, p2->mac_key, KEYSIZE);
	SHA256Update(&ctx, message, strlen(message));
	SHA256Final(mac2, &ctx);

	return memcmp(mac1, mac2, SHA256_DIGEST_LENGTH) == 0;
}

int
main(void)
{
	struct party alice, bob;

	if (dh_init(&alice) == 0 ||
	    dh_init(&bob) == 0 ||

	    dh_exchange(&alice, &bob) == 0 ||
	    dh_exchange(&bob, &alice) == 0)
		err(1, NULL);

	puts(dh_verify(&alice, &bob, "OK") ? "success" : "failure");

	exit(0);
}
