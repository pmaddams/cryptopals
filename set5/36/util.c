#include <sys/types.h>

#include <sha2.h>
#include <string.h>

#include "36.h"

int
ssend(int fd, char *s)
{
	size_t len;

	len = strlen(s);
	return send(fd, s, len, 0) == len;
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
