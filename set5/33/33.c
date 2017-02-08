#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#define G	"2"
#define P	"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"	\
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"	\
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"	\
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"	\
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"	\
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"	\
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"	\
		"fffffffffffff"

struct party {
	BIGNUM private;
	BIGNUM public;
	BIGNUM shared;
};

BIGNUM *g, *p;

int
generate(struct party *party)
{
	BN_CTX *ctx;
	uint8_t buf[BUFSIZ];

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;

	memset(party, 0, sizeof(*party));
	arc4random_buf(buf, BUFSIZ);

	if (BN_bin2bn(buf, BUFSIZ, &party->private) == 0 ||
	    BN_mod_exp(&party->public, g, &party->private, p, ctx) == 0)
		goto fail;

	BN_CTX_free(ctx);
	return 1;
fail:
	return 0;
}

int
exchange(struct party *p1, struct party *p2)
{
	BN_CTX *ctx;

	if ((ctx = BN_CTX_new()) == NULL ||
	    BN_mod_exp(&p1->shared, &p2->public, &p1->private, p, ctx) == 0 ||
	    BN_mod_exp(&p2->shared, &p1->public, &p2->private, p, ctx) == 0)
		goto fail;

	BN_CTX_free(ctx);
	return 1;
fail:
	return 0;
}

int
verify(struct party *p1, struct party *p2)
{
	return BN_cmp(&p1->shared, &p2->shared) == 0;
}

int
main(void)
{
	struct party alice, bob;

	if (BN_hex2bn(&g, G) == 0 ||
	    BN_hex2bn(&p, P) == 0 ||

	    generate(&alice) == 0 ||
	    generate(&bob) == 0 ||

	    exchange(&alice, &bob) == 0)
		err(1, NULL);

	puts(verify(&alice, &bob) ? "success" : "failure");

	exit(0);
}
