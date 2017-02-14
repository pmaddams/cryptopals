#include <sys/types.h>

#include <openssl/bn.h>

#define HASHSIZE	101
#define TIMEOUT		999

#define DECRYPT		0
#define ENCRYPT		1

struct rsa {
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *d;
};

int rsa_init(struct rsa *);
BIGNUM *rsa_crypt(struct rsa *, BIGNUM *, int);
