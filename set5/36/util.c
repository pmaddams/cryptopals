#include <sys/types.h>

#include <sha2.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "36.h"

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
	char *s;
	va_list ap;

	va_start(ap, fmt);
	if (vasprintf(&s, fmt, ap) == -1)
		goto fail;
	va_end(ap);

	return ssend(fd, s);
fail:
	return 0;
}

char *
srecv(int fd)
{
	char buf[8192];
	ssize_t nr;

	if ((nr = recv(fd, buf, sizeof(buf), 0)) == -1)
		goto fail;
	buf[nr] = '\0';

	return strdup(buf);
fail:
	return NULL;
}
