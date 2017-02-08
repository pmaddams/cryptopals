#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <err.h>
#include <netdb.h>
#include <sha2.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bn.h>

#include "38.h"

#define USERNAME "admin@secure.net"
#define PASSWORD "batman"

BN_CTX *bnctx;

BIGNUM *modulus, *generator, *multiplier, *verifier,
    *private_key, *public_key, *client_pubkey,
    *scrambler, *shared_s;

char *salt, *shared_k, *hmac;

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
make_scrambler(void)
{
	uint8_t buf[16];

	arc4random_buf(buf, 16);
	return BN_bin2bn(buf, 16, NULL);
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

BIGNUM *
make_shared_s(BIGNUM *client_pubkey, BIGNUM *verifier, BIGNUM *scrambler, BIGNUM *private_key, BIGNUM *modulus)
{
	BIGNUM *tmp;

	BN_CTX_start(bnctx);

	if ((shared_s = BN_new()) == NULL ||
	    (tmp = BN_CTX_get(bnctx)) == NULL ||

	    BN_mod_exp(tmp, verifier, scrambler, modulus, bnctx) == 0 ||
	    BN_mul(tmp, client_pubkey, tmp, bnctx) == 0 ||
	    BN_mod_exp(shared_s, tmp, private_key, modulus, bnctx) == 0)
		goto fail;

	BN_CTX_end(bnctx);

	return shared_s;
fail:
	return NULL;
}

int
main(void)
{
	int listenfd, connfd;
	pid_t pid;
	char *buf, *buf2, *p;
	size_t i;

	if ((bnctx = BN_CTX_new()) == NULL ||
	    init_params(&modulus, &generator, &multiplier) == 0 ||
	    (salt = make_salt()) == NULL ||
	    (private_key = make_private_key()) == NULL ||
	    (public_key = make_public_key(generator, private_key, modulus)) == NULL ||
	    (scrambler = make_scrambler()) == NULL ||
	    (listenfd = lo_listen(PORT)) == -1)
		err(1, NULL);

	for (;;) {
		if ((connfd = accept(listenfd, NULL, NULL)) == -1 ||
		    (pid = fork()) == -1)
			err(1, NULL);

		if (pid != 0) {
			close(connfd);
			continue;
		}
		close(listenfd);

		if ((buf = srecv(connfd)) == NULL)
			err(1, NULL);

		p = buf;
		if ((i = strcspn(p, " ")) > strlen(p)-2 ||
		    strncmp(p, USERNAME, i) != 0)
			errx(1, "invalid username");

		p += i+1;
		if ((client_pubkey = BN_new()) == NULL ||
		    BN_hex2bn(&client_pubkey, p) == 0)
			err(1, NULL);

		free(buf);

		if ((buf = BN_bn2hex(public_key)) == NULL ||
		    (buf2 = BN_bn2hex(scrambler)) == NULL ||
		    ssendf(connfd, "%s %s %s", salt, buf, buf2) == 0)
			err(1, NULL);

		free(buf);
		free(buf2);

		if ((shared_s = make_shared_s(client_pubkey, verifier, scrambler, private_key, modulus)) == NULL ||
		    (shared_k = make_shared_k(shared_s)) == NULL ||
		    (hmac = make_hmac(shared_k, salt)) == NULL ||

		    (buf = srecv(connfd)) == NULL ||
		    ssend(connfd, strcmp(buf, hmac) == 0 ? "OK" : "NO") == 0)
			err(1, NULL);

		break;
	}

	exit(0);
}
