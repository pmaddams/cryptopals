#include <sys/types.h>
#include <sys/socket.h>

#include <sha2.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "36.h"

#define TMPSIZ 8192

#define BLKSIZ 64

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
srp_generate_private_key(struct srp *srp)
{
	do
		if (BN_rand_range(srp->priv_key, srp->n) == 0)
			goto fail;
	while (BN_is_zero(srp->priv_key));

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

BIGNUM *
generate_scrambler(BIGNUM *client_pub_key, BIGNUM *server_pub_key)
{
	SHA2_CTX sha2ctx;
	size_t len;
	char *buf, hash[SHA256_DIGEST_LENGTH];

	SHA256Init(&sha2ctx);

	len = BN_num_bytes(client_pubkey);
	if ((buf = malloc(len)) == NULL ||
	    BN_bn2bin(client_pubkey, buf) == 0)
		goto fail;

	SHA256Update(&sha2ctx, buf, len);
	free(buf);

	len = BN_num_bytes(server_pubkey);
	if ((buf = malloc(len)) == NULL ||
	    BN_bn2bin(server_pubkey, buf) == 0)
		goto fail;

	SHA256Update(&sha2ctx, buf, len);
	free(buf);

	SHA256Final(hash, &sha2ctx);

	return BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);
fail:
	return NULL;
}

char *
hmac(char *shared_k, char *salt)
{
	char ipad[BLKSIZ], opad[BLKSIZ],
	    hash[SHA256_DIGEST_LENGTH];
	size_t i, len;
	SHA2_CTX sha2ctx;

	memset(ipad, '\x5c', BLKSIZ);
	memset(opad, '\x36', BLKSIZ);

	len = strlen(shared_k);
	for (i = 0; i < len; i++) {
		ipad[i] ^= shared_k[i];
		opad[i] ^= shared_k[i];
	}

	SHA256Init(&sha2ctx);
	SHA256Update(&sha2ctx, ipad, BLKSIZ);
	SHA256Update(&sha2ctx, salt, strlen(salt));
	SHA256Final(hash, &sha2ctx);

	SHA256Init(&sha2ctx);
	SHA256Update(&sha2ctx, opad, BLKSIZ);
	SHA256Update(&sha2ctx, hash, SHA256_DIGEST_LENGTH);

	return SHA256End(&sha2ctx, NULL);
}
