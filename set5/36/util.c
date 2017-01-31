#include <sys/types.h>

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "36.h"

int
params(BIGNUM **np, BIGNUM **gp, BIGNUM **kp)
{
	return BN_hex2bn(np, N) &&
	    BN_hex2bn(gp, G) &&
	    BN_hex2bn(kp, K);
}

int
privkey(BIGNUM **keyp)
{
	char buf[BUFSIZ];

	arc4random_buf(buf, BUFSIZ);

	return (*keyp = BN_bin2bn(buf, BUFSIZ, NULL)) != NULL;
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

void
xtoa(uint8_t *dst, size_t *dstlenp, char *src)
{
	size_t i, j, k;
	char c;
	static char buf[3];

	for (i = j = 0;; i++) {
		for (k = 0; k < 2;)
			if (isxdigit(c = src[j+k]))
				buf[k++] = c;
			else if (c != '\0')
				j++;
			else
				goto done;

		dst[i] = strtol(buf, NULL, 16);
		j += k;
	}
done:
	dst[i] = '\0';
	if (dstlenp != NULL)
		*dstlenp = i;
}

void
atox(char *dst, uint8_t *src, size_t srclen)
{
	while (srclen--) {
		snprintf(dst, 3, "%02x", *src);

		src++;
		dst += 2;
	}
}
