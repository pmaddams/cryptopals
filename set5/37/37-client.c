#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <err.h>
#include <netdb.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "37.h"

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

int
main(void)
{
	int connfd;
	char *buf;
	size_t i;

	if ((connfd = lo_connect(PORT)) == -1 ||
	    ssendf(connfd, "%s %d", USERNAME, 0) == 0)
		err(1, NULL);

	free(buf);

	if ((buf = srecv(connfd)) == NULL)
		err(1, NULL);

	if ((i = strcspn(buf, " ")) > strlen(buf)-2)
		errx(1, "invalid salt");
	buf[i] = '\0';

	if (ssend(connfd, make_hmac(SHA256Data("", 0, NULL), buf)) == 0)
		err(1, NULL);

	free(buf);

	if ((buf = srecv(connfd)) == NULL)
		err(1, NULL);

	puts(strcmp(buf, "OK") == 0 ? "success" : "failure");

	exit(0);
}
