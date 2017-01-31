#include <sys/types.h>

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "36.h"

int
init_params(BIGNUM **modp, BIGNUM **genp, BIGNUM **multp)
{
	return BN_hex2bn(modp, N) &&
	    BN_hex2bn(genp, G) &&
	    BN_hex2bn(multp, K);
}

BIGNUM *
make_private_key(void)
{
	char buf[BUFSIZ];

	arc4random_buf(buf, BUFSIZ);

	return BN_bin2bn(buf, BUFSIZ, NULL);
}

char *
input(void)
{
	char buf[BUFSIZ];

	if (fgets(buf, BUFSIZ, stdin) == NULL)
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
	char buf[BUFSIZ];

	va_start(ap, fmt);
	if (vsnprintf(buf, BUFSIZ, fmt, ap) == -1)
		goto fail;
	va_end(ap);

	return ssend(fd, buf);
fail:
	return 0;
}

char *
srecv(int fd)
{
	char buf[BUFSIZ];
	ssize_t nr;

	if ((nr = recv(fd, buf, BUFSIZ, 0)) == -1)
		goto fail;
	buf[nr] = '\0';

	return strdup(buf);
fail:
	return NULL;
}

uint8_t *
xtoa(char *src, size_t *dstlenp)
{
	size_t i, j, k, srclen;
	uint8_t *dst, buf[3];

	srclen = strlen(src);
	if ((dst = malloc(srclen/2)) == NULL)
		goto fail;

	buf[2] = '\0';
	for (i = j = 0; i < srclen; i += 2) {
		for (k = 0; k < 2; k++)
			if (!isxdigit(buf[k] = src[i+k]))
				goto fail;

		dst[j++] = strtol(buf, NULL, 16);
	}

	if (dstlenp != NULL)
		*dstlenp = j;

	return dst;
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
