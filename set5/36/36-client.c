#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <err.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "36.h"

#define POLL_STDIN	0
#define POLL_NETOUT	1
#define POLL_NETIN	2
#define POLL_STDOUT	3

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
	int fd;
	struct pollfd pfd[4];
	char buf[BUFSIZ];
	ssize_t nr;

	if ((fd = lo_connect(PORT)) == -1)
		err(1, NULL);

	pfd[POLL_STDIN].fd = STDIN_FILENO;
	pfd[POLL_STDIN].events = POLLIN;

	pfd[POLL_NETOUT].fd = fd;
	pfd[POLL_NETOUT].events = 0;

	pfd[POLL_NETIN].fd = fd;
	pfd[POLL_NETIN].events = POLLIN;

	pfd[POLL_STDOUT].fd = STDOUT_FILENO;
	pfd[POLL_STDOUT].events = 0;

	for (;;) {
		if (poll(pfd, 4, INFTIM) == -1)
			err(1, NULL);

		if (pfd[POLL_STDIN].revents & POLLIN) {
			if ((nr = read(STDIN_FILENO, buf, BUFSIZ)) == -1 ||
			    write(fd, buf, nr) < nr)
				err(1, NULL);
		}
		if (pfd[POLL_NETIN].revents & POLLIN) {
			if ((nr = read(fd, buf, BUFSIZ)) == -1 ||
			    write(STDOUT_FILENO, buf, nr) < nr)
				err(1, NULL);
		}
	}
}
