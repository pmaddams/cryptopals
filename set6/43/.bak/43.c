#include <openssl/bn.h>

#define P	"800000000000000089e1855218a0e7dac38136ffafa72eda7"	\
		"859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"	\
		"2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"	\
		"ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"	\
		"b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"	\
		"1a584471bb1"

#define Q	"f4f47f05794b256174bba6e9b396a7707e563c5b"

#define G	"5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"	\
		"458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"	\
		"322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"	\
		"0f5b64c36b625a097f1651fe775323556fe00b3608c887892"	\
		"878480e99041be601a62166ca6894bdd41a7054ec89f756ba"	\
		"9fc95302291"

struct dsa {
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *g;
	BIGNUM *priv_key;
	BIGNUM *pub_key;
};

int
dsa_init(struct dsa *dsa)
{
	if ((dsa->p = BN_new()) == NULL ||
	    (dsa->q = BN_new()) == NULL ||
	    (dsa->g = BN_new()) == NULL ||
	    (dsa->priv_key = BN_new()) == NULL ||
	    (dsa->pub_key = BN_new()) == NULL ||

	    BN_hex2bn(&dsa->p, P) == 0 ||
	    BN_hex2bn(&dsa->q, Q) == 0 ||
	    BN_hex2bn(&dsa->g, G) == 0)
		goto fail;

	return 1;
fail:
	return 0;
}

uint8_t *
dsa_sign(struct dsa *dsa, uint8_t *buf, size_t len)
{
}

int
dsa_verify(struct dsa *dsa, uint8_t *buf, size_t len, uint8_t *sig)
{
}

int
main(void)
{
}
