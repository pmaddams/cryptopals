#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <err.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PORT 12345

int
main(void)
{
	int fd;
	struct sockaddr_in sin;
	int c;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = htons(PORT);

	if ((fd = socket(sin.sin_family, SOCK_STREAM, 0)) == -1 ||
	    connect(fd, (struct sockaddr *) &sin, sizeof(sin)) == -1)
		err(1, NULL);

	while ((c = getchar()) != EOF)
		if (write(fd, &c, 1) == -1)
			err(1, NULL);

	exit(0);
}
