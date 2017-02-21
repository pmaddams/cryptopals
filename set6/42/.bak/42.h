#include <sys/types.h>

#include <openssl/bn.h>

#define DATA	"hi mom"

#define E	"3"
#define BITS	1024

uint8_t *asn1_sign(uint8_t *, size_t, size_t *);
int cubert(BIGNUM *, BIGNUM *, BN_CTX *);
void putx(uint8_t *, size_t);
