#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <err.h>
#include <netdb.h>
#include <sha2.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "36.h"

BIGNUM *n, *g, *k, *private, *public;
char *email, *password, *salt;

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

char *
make_salt(void)
{
	uint32_t num;

	num = arc4random();

	return atox((uint8_t *) &num, sizeof(num));
}

int
main(void)
{
	int listenfd, connfd;
	SHA2_CTX ctx;
	char *buf, sha[SHA256_DIGEST_LENGTH];
	BIGNUM *x;

	if (init_params(&n, &g, &k) == 0 ||
	    (private = make_private_key()) == NULL ||
	    (salt = make_salt()) == NULL ||

	    (listenfd = lo_listen(PORT)) == -1 ||
	    (connfd = accept(listenfd, NULL, NULL)) == -1 ||

	    ssend(connfd, salt) == 0 ||
	    (buf = srecv(connfd)) == 0)
		err(1, NULL);

	free(buf);

	if (ssend(connfd, "email: ") == 0 ||
	    (email = srecv(connfd)) == NULL ||

	    ssend(connfd, "password: ") == 0 ||
	    (password = srecv(connfd)) == NULL)
		err(1, NULL);

	/*
	SHA256Init(&ctx);
	SHA256Update(&ctx, (uint8_t *) &salt, 4);
	SHA256Update(&ctx, password, strlen(password));
	SHA256Final(sha, &ctx);

	if ((x = BN_bin2bn(sha, SHA256_DIGEST_LENGTH, NULL)) == NULL)
		err(1, NULL);
	*/

	exit(0);
}
