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

#define BLKSIZ 64

int
init_params(BIGNUM **modp, BIGNUM **genp)
{
	return BN_hex2bn(modp, N) &&
	    BN_hex2bn(genp, G);
}

BIGNUM *
make_private_key(void)
{
	char buf[BUFSIZ];

	arc4random_buf(buf, BUFSIZ);

	return BN_bin2bn(buf, BUFSIZ, NULL);
}

BIGNUM *
make_public_key(BIGNUM *generator, BIGNUM *private_key, BIGNUM *modulus)
{
	BN_CTX *bnctx;
	BIGNUM *public_key;

	if ((bnctx = BN_CTX_new()) == NULL ||
	    (public_key = BN_new()) == NULL ||
	    BN_mod_exp(public_key, generator, private_key, modulus, bnctx) == 0)
		goto fail;

	BN_CTX_free(bnctx);

	return public_key;
fail:
	return NULL;
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
	char buf[TMPSIZ];

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

char *
make_shared_k(BIGNUM *shared_s)
{
	size_t len;
	char *buf, *res;

	len = BN_num_bytes(shared_s);
	if ((buf = malloc(len)) == NULL ||
	    BN_bn2bin(shared_s, buf) == 0 ||
	    (res = SHA256Data(buf, len, NULL)) == NULL)
		goto fail;

	free(buf);
	return res;
fail:
	return NULL;
}

char *
make_hmac(char *shared_k, char *salt)
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
