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

BIGNUM *modulus, *generator, *multiplier,
    *private_key, *public_key, *shared_s, *shared_k,
    *verifier, *scrambler;

char *email, *password, *salt, *client_pubkey;

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

BIGNUM *
make_public_key(void)
{
	SHA2_CTX ctx;
	uint8_t sha[SHA256_DIGEST_LENGTH];

	SHA256Init(&ctx);
	SHA256Update(&ctx, salt, strlen(salt));
	SHA256Update(&ctx, password, strlen(password));
	SHA256Final(sha, &ctx);
}

int
main(void)
{
	int listenfd, connfd;
	char *buf;

	if (init_params(&modulus, &generator, &multiplier) == 0 ||
	    (private_key = make_private_key()) == NULL ||
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

	exit(0);
}
