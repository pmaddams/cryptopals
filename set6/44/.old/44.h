#include <sys/types.h>

#include <openssl/bn.h>
#include <openssl/dsa.h>

#define FILENAME "DATA"

struct entry {
	BIGNUM *m;
	DSA_SIG *sig;
};

struct data {
	struct entry **entries;
	size_t len;
};
