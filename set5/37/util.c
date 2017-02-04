#include <sys/types.h>

#include <limits.h>
#include <sha2.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "37.h"

#define TMPSIZ 8192

#define BLKSIZ 64

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
make_shared_k(BIGNUM *shared_s)
{
	return SHA256Data("", 0, NULL);
}

char *
make_hmac(char *shared_k, char *salt)
{
	char ipad[BLKSIZ], opad[BLKSIZ], hash[SHA256_DIGEST_LENGTH];
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
