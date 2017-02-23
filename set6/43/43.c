#include <openssl/bn.h>

struct dsa {
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *g;
	BIGNUM *x;
	BIGNUM *y;
};

int
dsa_init(struct dsa *dsa)
{
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
