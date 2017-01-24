#include <sys/types.h>

#include <err.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#define P	"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"	\
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"	\
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"	\
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"	\
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"	\
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"	\
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"	\
		"fffffffffffff"
#define G	"2"

#define BLKSIZ	16

struct party {
	BIGNUM private;
	BIGNUM public;
	BIGNUM shared;

	uint8_t key[BLKSIZ];
	uint8_t iv[BLKSIZ];

	uint8_t *message;
};

BIGNUM *p, *g;
BN_CTX *bnctx;

int
generate(struct party *party)
{
	uint8_t buf[BUFSIZ];

	memset(party, 0, sizeof(*party));
	arc4random_buf(buf, BUFSIZ);

	return BN_bin2bn(buf, BUFSIZ, &party->private) &&
	    BN_mod_exp(&party->public, g, &party->private, p, bnctx);
}

int
send_key(struct party *party, BIGNUM *b)
{
	return BN_mod_exp(&party->shared, b, &party->private, p, bnctx);
}

int
intercept(struct party *p1, struct party *mitm, struct party *p2)
{
}

int
params(struct party *party)
{
	size_t len;
	uint8_t *buf, hash[SHA1_DIGEST_LENGTH];
	SHA1_CTX sha1ctx;

	len = BN_num_bytes(&party->shared);

	if ((buf = malloc(len)) == NULL)
		goto fail;

	BN_bn2bin(&party->shared, buf);

	SHA1Init(&sha1ctx);
	SHA1Update(&sha1ctx, buf, len);
	SHA1Final(hash, &sha1ctx);

	memcpy(party->key, hash, BLKSIZ);
	arc4random_buf(party->iv, BLKSIZ);

	free(buf);
	return 1;
fail:
	return 0;
}

int
main(void)
{
	struct party alice, bob, chuck;

	if ((bnctx = BN_CTX_new()) == NULL ||
	    BN_hex2bn(&p, P) == 0 ||
	    BN_hex2bn(&g, G) == 0 ||
	    generate(&alice) == 0 ||
	    generate(&bob) == 0)
		err(1, NULL);

	exit(0);
}
