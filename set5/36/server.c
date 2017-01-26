#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PORT 12345

int
main(void)
{
	int listenfd, connfd;
	struct sockaddr_in sin;
	FILE *fp;
	int c;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(PORT);

	if ((listenfd = socket(sin.sin_family, SOCK_STREAM, 0)) == -1 ||
	    bind(listenfd, (struct sockaddr *) &sin, sizeof(sin)) == -1 ||
	    listen(listenfd, 1) == -1)
		err(1, NULL);

	for (;;) {
		if ((connfd = accept(listenfd, NULL, NULL)) == -1 ||
		    (fp = fdopen(connfd, "r")) == NULL)
			err(1, NULL);

		while ((c = getc(fp)) != EOF)
			putchar(toupper(c));
	}
}
