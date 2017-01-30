#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <err.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "36.h"

int
lo_connect(in_port_t port)
{
	struct sockaddr_in sin;
	int fd;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = htons(port);

	if ((fd = socket(sin.sin_family, SOCK_STREAM, 0)) == -1 ||
	    connect(fd, (struct sockaddr *) &sin, sizeof(sin)) == -1)
		goto fail;

	return fd;
fail:
	return -1;
}

char *
input(void)
{
	char *buf, *lbuf;
	size_t len;

	if ((buf = fgetln(stdin, &len)) == NULL)
		goto fail;
	if (buf[len-1] == '\n')
		len--;
	if (len == 0)
		goto fail;

	if ((lbuf = malloc(len+1)) == NULL)
		goto fail;
	memcpy(lbuf, buf, len);
	lbuf[len] = '\0';

	return lbuf;
fail:
	return NULL;
}

int
main(void)
{
	int connfd;
	char *buf, *email, *password;

	if ((connfd = lo_connect(PORT)) == -1 ||
	    (buf = srecv(connfd)) == 0)
		err(1, NULL);

	printf("%s", buf);
	free(buf);

	if ((email = input()) == NULL ||
	    ssend(connfd, email) == 0 ||
	    (buf = srecv(connfd)) == 0)
		err(1, NULL);

	printf("%s", buf);
	free(buf);

	if ((password = input()) == NULL ||
	    ssend(connfd, password) == 0 ||
	    (buf = srecv(connfd)) == 0)
		err(1, NULL);

	printf("%s", buf);
	free(buf);

	exit(0);
}
