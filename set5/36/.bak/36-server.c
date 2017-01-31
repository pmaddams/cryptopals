#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <ctype.h>
#include <err.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>

#include "36.h"

int
lo_listen(in_port_t port)
{
	struct sockaddr_in sin;
	int fd;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = htons(port);

	if ((fd = socket(sin.sin_family, SOCK_STREAM, 0)) == -1 ||
	    bind(fd, (struct sockaddr *) &sin, sizeof(sin)) == -1 ||
	    listen(fd, 1) == -1)
		goto fail;

	return fd;
fail:
	return -1;
}

int
main(void)
{
	int listenfd, connfd;
	char *email, *password;

	if ((listenfd = lo_listen(PORT)) == -1 ||
	    (connfd = accept(listenfd, NULL, NULL)) == -1 ||

	    ssend(connfd, "email: ") == 0 ||
	    (email = srecv(connfd)) == NULL ||
	    ssend(connfd, "password: ") == 0 ||
	    (password = srecv(connfd)) == NULL ||
	    ssendf(connfd, "email: %s\npassword: %s\n", email, password) == 0)
		err(1, NULL);

	exit(0);
}
