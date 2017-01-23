#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#define P							\
	"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"	\
	"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"	\
	"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"	\
	"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"	\
	"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"	\
	"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"	\
	"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"	\
	"fffffffffffff"
#define G							\
	"2"

struct party {
	BIGNUM private;
	BIGNUM public;
	BIGNUM shared;
};

BIGNUM *p, *g;
BN_CTX *ctx;

int
generate(struct party *party)
{
	uint8_t buf[BUFSIZ];

	memset(party, 0, sizeof(*party));
	arc4random_buf(buf, BUFSIZ);

	return BN_bin2bn(buf, BUFSIZ, &party->private) &&
	    BN_mod_exp(&party->public, g, &party->private, p, ctx);
}

int
exchange(struct party *p1, struct party *p2)
{
	return BN_mod_exp(&p1->shared, &p2->public, &p1->private, p, ctx) &&
	    BN_mod_exp(&p2->shared, &p1->public, &p2->private, p, ctx);
}

int
main(void)
{
	struct party alice, bob;

	if ((ctx = BN_CTX_new()) == NULL ||
	    BN_hex2bn(&p, P) == 0 ||
	    BN_hex2bn(&g, G) == 0 ||
	    generate(&alice) == 0 ||
	    generate(&bob) == 0 ||
	    exchange(&alice, &bob) == 0)
		err(1, NULL);

	puts(BN_cmp(&alice.shared, &bob.shared) == 0 ? "success" : "failure");

	exit(0);
}
