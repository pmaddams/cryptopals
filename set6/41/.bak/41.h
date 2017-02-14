#include <sys/types.h>

#include <openssl/bn.h>

#define VERBOSE

#define S		"2"

#define E		"3"
#define BITS		2048

#define HASHSIZE	101
#define TIMEOUT		999

#define DECRYPT		0
#define ENCRYPT		1

struct message {
	time_t timestamp;
	char *buf;
};

struct entry {
	time_t timestamp;
	uint8_t *hash;
	struct entry *next;
};

struct rsa {
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *d;
};

BIGNUM *invmod(BIGNUM *, BIGNUM *);
int rsa_init(struct rsa *);
BIGNUM *rsa_crypt(struct rsa *, BIGNUM *, int);
