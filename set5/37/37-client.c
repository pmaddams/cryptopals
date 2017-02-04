#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <err.h>
#include <netdb.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "37.h"

char *salt, *shared_k, *hmac;

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

BIGNUM *
zero_key(void)
{
	BIGNUM *n;

	if ((n = BN_new()) == NULL ||
	    BN_zero(n) == 0)
		goto fail;

	return n;
fail:
	return NULL;
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

	salt = buf;

	if ((shared_k = make_shared_k(zero_key())) == NULL ||
	    (hmac = make_hmac(shared_k, salt)) == NULL)
		err(1, NULL);

	if (ssend(connfd, hmac) == 0 ||
	    (buf = srecv(connfd)) == NULL)
		err(1, NULL);

	puts(strcmp(buf, "OK") == 0 ? "success" : "failure");

	exit(0);
}
