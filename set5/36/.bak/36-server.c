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

BN_CTX *bnctx;

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
make_verifier(char *salt, char *password)
{
	SHA2_CTX sha2ctx;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	BIGNUM *x;

	SHA256Init(&sha2ctx);
	SHA256Update(&sha2ctx, salt, strlen(salt));
	SHA256Update(&sha2ctx, password, strlen(password));
	SHA256Final(hash, &sha2ctx);

	if ((x = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL)) == NULL ||
	    (verifier = BN_new()) == NULL ||
	    BN_mod_exp(verifier, generator, x, modulus, bnctx) == 0)
		goto fail;

	return verifier;
fail:
	return NULL;
}

int
main(void)
{
	int listenfd, connfd;
	char *buf;

	if ((bnctx = BN_CTX_new()) == NULL ||
	    init_params(&modulus, &generator, &multiplier) == 0 ||
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
	    (password = srecv(connfd)) == NULL ||

	    (verifier = make_verifier(salt, password)) == NULL)
		err(1, NULL);

	exit(0);
}
