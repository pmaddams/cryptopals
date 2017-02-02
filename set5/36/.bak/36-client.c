#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <err.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "36.h"

BN_CTX *bnctx;

BIGNUM *modulus, *generator, *multiplier,
    *private_key, *public_key, *server_pubkey,
    *shared_s, *shared_k,
    *scrambler;

char *username, *password;

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
make_public_key(BIGNUM *generator, BIGNUM *private_key, BIGNUM *modulus)
{
	if ((public_key = BN_new()) == NULL ||
	    BN_mod_exp(public_key, generator, private_key, modulus, bnctx) == 0)
		goto fail;

	return public_key;
fail:
	return NULL;
}

int
main(void)
{
	int connfd;
	char *buf;

	if ((bnctx = BN_CTX_new()) == NULL ||
	    init_params(&modulus, &generator, &multiplier) == 0 ||
	    (private_key = make_private_key()) == NULL ||
	    (public_key = make_public_key(generator, private_key, modulus)) == NULL)
		err(1, NULL);

	print("username: ");
	if ((username = input()) == NULL ||
	    (buf = BN_bn2hex(public_key)) == NULL ||
	    (connfd = lo_connect(PORT)) == -1 ||
	    ssendf(connfd, "%s %s", username, buf) == 0)
		err(1, NULL);

	exit(0);
}
