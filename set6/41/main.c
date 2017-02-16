#include <sys/types.h>

#include <err.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bn.h>

#include "41.h"

char *
encrypt_message(struct rsa *rsa, char *buf)
{
	struct message msg;
	BIGNUM *in, *out;
	char *res;

	time(&msg.timestamp);
	msg.buf = buf;

	if ((in = BN_bin2bn((uint8_t *) &msg, sizeof(msg), NULL)) == NULL ||
	    (out = rsa_crypt(rsa, in, ENCRYPT)) == NULL ||
	    (res = BN_bn2hex(out)) == NULL)
		goto fail;

	free(in);
	free(out);

	return res;
fail:
	return NULL;
}

int
check_message(char *enc)
{
	time_t cur;
	SHA2_CTX ctx;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	size_t h;
	static struct entry *tab[HASHSIZE];
	struct entry *entry, *prev, *next;

	if (time(&cur) == -1)
		goto fail;

	SHA256Init(&ctx);
	SHA256Update(&ctx, enc, strlen(enc));
	SHA256Final(hash, &ctx);

	h = *(size_t *) hash % HASHSIZE;

	for (prev = NULL, entry = tab[h]; entry != NULL;)
		if (cur - entry->timestamp > TIMEOUT) {
			next = entry->next;

			if (prev == NULL)
				tab[h] = next;
			else
				prev->next = next;

			free(entry->hash);
			free(entry);

			entry = next;
		} else if (memcmp(hash, entry->hash, SHA256_DIGEST_LENGTH) == 0)
			goto fail;
		else {
			prev = entry;
			entry = entry->next;
		}

	if ((entry = malloc(sizeof(*entry))) == NULL ||
	    (entry->hash = malloc(SHA256_DIGEST_LENGTH)) == NULL)
		goto fail;

	entry->timestamp = cur;
	memcpy(entry->hash, hash, SHA256_DIGEST_LENGTH);
	entry->next = tab[h];
	tab[h] = entry;

	return 1;
fail:
	return 0;
}

char *
decrypt_blob(struct rsa *rsa, char *enc)
{
	BIGNUM *in, *out;
	char *res;

	if (check_message(enc) == 0 ||
	    (in = BN_new()) == NULL ||
	    BN_hex2bn(&in, enc) == 0 ||
	    (out = rsa_crypt(rsa, in, DECRYPT)) == NULL ||
	    (res = BN_bn2hex(out)) == NULL)
		goto fail;

	free(in);
	free(out);

	return res;
fail:
	return NULL;
}

char *
decode_blob(char *buf)
{
	BIGNUM *bn;
	struct message msg;
	char *res;

	if ((bn = BN_new()) == NULL ||
	    BN_hex2bn(&bn, buf) == 0 ||
	    BN_bn2bin(bn, (uint8_t *) &msg) == 0 ||
	    (res = strdup(msg.buf)) == NULL)
		goto fail;

	free(bn);
	return res;
fail:
	return NULL;
}

char *
decrypt_message(struct rsa *rsa, char *enc)
{
	char *dec, *res;

	if ((dec = decrypt_blob(rsa, enc)) == NULL ||
	    (res = decode_blob(dec)) == NULL)
		goto fail;

	free(dec);
	return res;
fail:
	return NULL;
}

char *
crack_message(struct rsa *rsa, char *enc)
{
	BN_CTX *ctx;
	BIGNUM *s, *c, *cprime, *p, *pprime, *denom;
	char *encprime, *decprime, *dec, *res;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((s = BN_CTX_get(ctx)) == NULL ||
	    (c = BN_CTX_get(ctx)) == NULL ||
	    (cprime = BN_CTX_get(ctx)) == NULL ||
	    (p = BN_CTX_get(ctx)) == NULL ||
	    (pprime = BN_CTX_get(ctx)) == NULL ||
	    (denom = BN_CTX_get(ctx)) == NULL ||

	    BN_dec2bn(&s, S) == 0 ||
	    BN_hex2bn(&c, enc) == 0 ||

	    BN_mod_exp(cprime, s, rsa->e, rsa->n, ctx) == 0 ||
	    BN_mod_mul(cprime, cprime, c, rsa->n, ctx) == 0 ||

	    (encprime = BN_bn2hex(cprime)) == NULL ||
	    (decprime = decrypt_blob(rsa, encprime)) == NULL ||

	    BN_hex2bn(&pprime, decprime) == 0 ||
	    invmod(denom, s, rsa->n, ctx) == 0 ||

	    BN_mod_mul(p, pprime, denom, rsa->n, ctx) == 0 ||
	    (dec = BN_bn2hex(p)) == NULL ||
	    (res = decode_blob(dec)) == NULL)
		goto fail;

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	free(encprime);
	free(decprime);
	free(dec);

	return res;
fail:
	return NULL;
}

int
main(int argc, char **argv)
{
	struct rsa rsa;
	char *enc, *dec, *dec2;

	if (argc == 1) {
		fprintf(stderr, "usage: %s string ...\n", argv[0]);
		exit(1);
	}

	if (rsa_init(&rsa) == 0)
		err(1, NULL);

	while (argc > 1) {
		if ((enc = encrypt_message(&rsa, argv[1])) == NULL ||
		    (dec = decrypt_message(&rsa, enc)) == NULL ||
		    (dec2 = crack_message(&rsa, enc)) == NULL)
			err(1, NULL);

		if (strcmp(dec, dec2) != 0)
			errx(1, "crack failed");

		puts(dec2);

		free(enc);	
		free(dec);	
		free(dec2);

		argc--;
		argv++;
	}

	exit(0);
}
