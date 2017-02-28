#include <sys/types.h>
#include <sys/socket.h>

#include <sha2.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "38.h"

#define TMPSIZ 8192

struct srp *
srp_new(void)
{
	struct srp *srp;

	if ((srp = malloc(sizeof(*srp))) == NULL ||
	    (srp->n = BN_new()) == NULL ||
	    (srp->g = BN_new()) == NULL ||
	    (srp->k = BN_new()) == NULL ||
	    (srp->u = BN_new()) == NULL ||
	    (srp->priv_key = BN_new()) == NULL ||
	    (srp->pub_key = BN_new()) == NULL ||

	    BN_hex2bn(&srp->n, N) == 0 ||
	    BN_hex2bn(&srp->g, G) == 0 ||
	    BN_hex2bn(&srp->k, K) == 0)
		goto fail;

	return srp;
fail:
	return NULL;
}

int
srp_generate_priv_key(struct srp *srp)
{
	do
		if (BN_rand_range(srp->priv_key, srp->n) == 0)
			goto fail;
	while (BN_is_zero(srp->priv_key));

	return 1;
fail:
	return 0;
}

int
srp_generate_pub_key(struct srp *srp)
{
	BN_CTX *ctx;

	if ((ctx = BN_CTX_new()) == NULL ||
	    BN_mod_exp(srp->pub_key, srp->g, srp->priv_key, srp->n, ctx) == 0)
		goto fail;

	BN_CTX_free(ctx);

	return 1;
fail:
	return 0;
}

char *
input(void)
{
	char buf[TMPSIZ];

	if (fgets(buf, TMPSIZ, stdin) == NULL)
		goto fail;
	buf[strcspn(buf, "\n")] = '\0';

	return strdup(buf);
fail:
	return NULL;
}

void
print(char *s)
{
	fputs(s, stdout);
}

int
ssend(int fd, char *s)
{
	size_t len;

	len = strlen(s);
	return send(fd, s, len, 0) == len;
}

int
ssendf(int fd, char *fmt, ...)
{
	va_list ap;
	static char buf[TMPSIZ];

	va_start(ap, fmt);
	if (vsnprintf(buf, TMPSIZ, fmt, ap) == -1)
		goto fail;
	va_end(ap);

	return ssend(fd, buf);
fail:
	return 0;
}

char *
srecv(int fd)
{
	char buf[TMPSIZ];
	ssize_t nr;

	if ((nr = recv(fd, buf, TMPSIZ, 0)) == -1)
		goto fail;
	buf[nr] = '\0';

	return strdup(buf);
fail:
	return NULL;
}

char *
atox(uint8_t *src, size_t srclen)
{
	size_t i, j;
	char *dst;

	if ((dst = malloc(srclen*2+1)) == NULL)
		goto done;

	for (i = j = 0; i < srclen; i++, j += 2)
		snprintf(dst+j, 3, "%02x", src[i]);
done:
	return dst;
}

int
generate_scrambler(BIGNUM *res, BIGNUM *client_pub_key, BIGNUM *server_pub_key)
{
	SHA2_CTX sha2ctx;
	size_t len;
	char *buf, hash[SHA256_DIGEST_LENGTH];

	SHA256Init(&sha2ctx);

	len = BN_num_bytes(client_pub_key);
	if ((buf = malloc(len)) == NULL ||
	    BN_bn2bin(client_pub_key, buf) == 0)
		goto fail;

	SHA256Update(&sha2ctx, buf, len);
	free(buf);

	len = BN_num_bytes(server_pub_key);
	if ((buf = malloc(len)) == NULL ||
	    BN_bn2bin(server_pub_key, buf) == 0)
		goto fail;

	SHA256Update(&sha2ctx, buf, len);
	free(buf);

	SHA256Final(hash, &sha2ctx);

	return BN_bin2bn(hash, SHA256_DIGEST_LENGTH, res) != NULL;
fail:
	return 0;
}

void
generate_hmac(char *res, struct state *state)
{
	char ipad[SHA256_BLOCK_LENGTH],
	    opad[SHA256_BLOCK_LENGTH],
	    hash[SHA256_DIGEST_LENGTH];
	size_t i, len;
	SHA2_CTX sha2ctx;

	memset(ipad, '\x5c', SHA256_BLOCK_LENGTH);
	memset(opad, '\x36', SHA256_BLOCK_LENGTH);

	for (i = 0; i < KEYSIZE; i++) {
		ipad[i] ^= state->enc_key[i];
		opad[i] ^= state->enc_key[i];
	}

	SHA256Init(&sha2ctx);
	SHA256Update(&sha2ctx, ipad, SHA256_BLOCK_LENGTH);
	SHA256Update(&sha2ctx, state->salt, strlen(state->salt));
	SHA256Final(hash, &sha2ctx);

	SHA256Init(&sha2ctx);
	SHA256Update(&sha2ctx, opad, SHA256_BLOCK_LENGTH);
	SHA256Update(&sha2ctx, hash, SHA256_DIGEST_LENGTH);
	SHA256End(&sha2ctx, res);
}
