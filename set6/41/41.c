#include <sys/types.h>

#include <err.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#define S		"2"

#define E		"3"
#define BITS		2048

#define MSGSIZE		128

#define HASHSIZE	101
#define TIMEOUT		999

struct msg {
	time_t timestamp;
	char buf[MSGSIZE];
};

struct entry {
	time_t timestamp;
	uint8_t *hash;
	struct entry *next;
};

int
invmod(BIGNUM *res, BIGNUM *bn, BIGNUM *modulus, BN_CTX *ctx)
{
	BIGNUM *out, *remainder, *quotient, *x1, *x2, *t1, *t2;

	if (BN_is_zero(bn) || BN_is_zero(modulus))
		goto fail;
	if (BN_is_one(bn) || BN_is_one(modulus))
		return BN_copy(res, BN_value_one()) != NULL;

	if ((out = BN_CTX_get(ctx)) == NULL ||
	    (remainder = BN_CTX_get(ctx)) == NULL ||
	    (quotient = BN_CTX_get(ctx)) == NULL ||
	    (x1 = BN_CTX_get(ctx)) == NULL ||
	    (x2 = BN_CTX_get(ctx)) == NULL ||
	    (t1 = BN_CTX_get(ctx)) == NULL ||
	    (t2 = BN_CTX_get(ctx)) == NULL ||

	    BN_copy(out, bn) == NULL ||
	    BN_copy(remainder, modulus) == NULL ||
	    BN_one(x1) == 0 ||
	    BN_zero(x2) == 0)
		goto fail;

	while (!BN_is_zero(remainder)) {
		if (BN_div(quotient, t1, out, remainder, ctx) == 0 ||
		    BN_copy(out, remainder) == NULL ||
		    BN_copy(remainder, t1) == NULL ||

		    BN_copy(t1, x2) == NULL ||
		    BN_mul(t2, quotient, x2, ctx) == 0 ||
		    BN_sub(x2, x1, t2) == 0 ||
		    BN_copy(x1, t1) == NULL)
			goto fail;
	}

	if (!BN_is_one(out) ||
	    BN_nnmod(out, x1, modulus, ctx) == 0)
		goto fail;

	return BN_copy(res, out) != NULL;
fail:
	return 0;
}

char *
encrypt_msg(RSA *rsa, char *buf)
{
	struct msg msg;
	ssize_t rsa_size;
	char *enc, *res;
	BIGNUM *bn;

	time(&msg.timestamp);
	strlcpy(msg.buf, buf, MSGSIZE);

	rsa_size = RSA_size(rsa);
	if ((enc = malloc(rsa_size)) == NULL ||

	    RSA_public_encrypt(rsa_size, (uint8_t *) &msg, enc, rsa, RSA_NO_PADDING) == 0 ||

	    (bn = BN_new()) == NULL ||
	    BN_bin2bn(enc, rsa_size, bn) == 0 ||
	    (res = BN_bn2hex(bn)) == NULL)
		goto fail;

	free(enc);
	BN_free(bn);

	return res;
fail:
	return NULL;
}

int
check_msg(char *enc)
{
	time_t cur;
	SHA2_CTX ctx;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	size_t h;
	static struct entry *tab[HASHSIZE];
	struct entry *entry, *prev, *next;

	time(&cur);

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
decrypt_blob(RSA *rsa, char *enc)
{
	ssize_t rsa_size;
	char *in, *out, *res;
	BIGNUM *bn;

	if (check_msg(enc) == 0)
		goto fail;

	rsa_size = RSA_size(rsa);
	if ((in = malloc(rsa_size)) == NULL ||
	    (out = malloc(rsa_size)) == NULL ||

	    (bn = BN_new()) == NULL ||
	    BN_hex2bn(&bn, enc) == 0 ||
	    BN_bn2bin(bn, in) == 0 ||

	    RSA_private_decrypt(rsa_size, in, out, rsa, RSA_NO_PADDING) == 0 ||

	    BN_bin2bn(out, rsa_size, bn) == 0 ||
	    (res = BN_bn2hex(bn)) == NULL)
		goto fail;

	free(in);
	free(out);
	BN_free(bn);

	return res;
fail:
	return NULL;
}

char *
decode_blob(RSA *rsa, char *dec)
{
	char *buf, *res;
	BIGNUM *bn;
	struct msg msg;

	if ((buf = malloc(RSA_size(rsa))) == NULL ||

	    (bn = BN_new()) == NULL ||
	    BN_hex2bn(&bn, dec) == 0 ||
	    BN_bn2bin(bn, buf) == 0)
		goto fail;

	memcpy(&msg, buf, sizeof(msg));
	if ((res = strdup(msg.buf)) == NULL)
		goto fail;

	free(buf);
	free(bn);

	return res;
fail:
	return NULL;
}

char *
decrypt_msg(RSA *rsa, char *enc)
{
	char *dec, *res;

	if ((dec = decrypt_blob(rsa, enc)) == NULL ||
	    (res = decode_blob(rsa, dec)) == NULL)
		goto fail;

	free(dec);
	return res;
fail:
	return NULL;
}

char *
crack_msg(RSA *rsa, char *enc)
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
	    (res = decode_blob(rsa, dec)) == NULL)
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
	BIGNUM *e;
	RSA *rsa;
	char *enc, *dec, *dec2;

	if (argc == 1) {
		fprintf(stderr, "usage: %s string ...\n", argv[0]);
		exit(1);
	}

	if ((e = BN_new()) == NULL ||
	    BN_dec2bn(&e, E) == 0 ||

	    (rsa = RSA_new()) == NULL ||
	    RSA_generate_key_ex(rsa, BITS, e, NULL) == 0)
		err(1, NULL);

	while (argc > 1) {
		if ((enc = encrypt_msg(rsa, argv[1])) == NULL ||
		    (dec = decrypt_msg(rsa, enc)) == NULL ||
		    (dec2 = crack_msg(rsa, enc)) == NULL)
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
