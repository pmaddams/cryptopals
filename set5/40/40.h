#include <openssl/bn.h>

#define E	"3"
#define BITS	2048

int cubert(BIGNUM *, BIGNUM *, BN_CTX *);
int invmod(BIGNUM *, BIGNUM *, BIGNUM *, BN_CTX *);
