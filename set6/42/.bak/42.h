#include <sys/types.h>

#include <openssl/bn.h>

#define DATA		"hi mom"

#define E		"3"
#define BITS		1024

int cubert(BIGNUM *, BIGNUM *, BN_CTX *);
uint8_t *make_asn1(uint8_t *, size_t, size_t *);
