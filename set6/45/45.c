#include <sys/types.h>

#include <err.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/dsa.h>

#define BITS 1024

int
main(int argc, char **argv)
{
	DSA *dsa;
	SHA2_CTX ctx;
	uint8_t *sig, hash[SHA256_DIGEST_LENGTH];
	size_t dsa_size;
	int siglen;
	char *s;

	if (argc == 1) {
		fprintf(stderr, "usage: %s string ...\n", argv[0]);
		exit(1);
	}

	if ((dsa = DSA_new()) == NULL ||

	    DSA_generate_parameters_ex(dsa, BITS, NULL, 0, NULL, NULL, NULL) == 0 ||
	    DSA_generate_key(dsa) == 0 ||

	    BN_copy(dsa->g, dsa->p) == 0 ||
	    BN_add(dsa->g, dsa->g, BN_value_one()) == 0)
		err(1, NULL);

	dsa_size = DSA_size(dsa);
	if ((sig = malloc(dsa_size)) == NULL)
		err(1, NULL);

	arc4random_buf(hash, SHA256_DIGEST_LENGTH);
	DSA_sign(0, hash, SHA256_DIGEST_LENGTH, sig, &siglen, dsa);

	while (argc > 1) {
		s = argv[1];

		SHA256Init(&ctx);
		SHA256Update(&ctx, s, strlen(s));
		SHA256Final(hash, &ctx);

		puts(DSA_verify(0, hash, SHA256_DIGEST_LENGTH, sig, siglen, dsa) ? "success" : "failure");

		argc--;
		argv++;
	}

	exit(0);
}
