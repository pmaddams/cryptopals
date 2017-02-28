#include <sys/types.h>
#include <sys/socket.h>

#include <sha2.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "37.h"

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
	    (srp->v = BN_new()) == NULL ||
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
