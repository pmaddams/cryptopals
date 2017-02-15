#include <openssl/bn.h>

#define VERBOSE

#define E	"3"
#define BITS	2048

struct rsa {
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *n;
	BIGNUM *e;
};

int cubert(BIGNUM *, BIGNUM *, BN_CTX *);
int invmod(BIGNUM *, BIGNUM *, BIGNUM *, BN_CTX *);
