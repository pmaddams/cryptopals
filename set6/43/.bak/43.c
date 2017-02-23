#include <openssl/bn.h>

struct dsa {
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *g;
	BIGNUM *x;
	BIGNUM *y;
};

dsa_sign()
{
}

dsa_verify()
{
}

int
main(void)
{
}
