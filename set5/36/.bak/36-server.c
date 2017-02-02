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

#define USERNAME "admin@secure.net"
#define PASSWORD "batman"

BN_CTX *bnctx;

BIGNUM *modulus, *generator, *multiplier, *verifier,
    *private_key, *public_key, *client_pubkey,
    *scrambler, *shared_s, *shared_k;

char *salt;

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
make_verifier(char *salt)
{
	SHA2_CTX sha2ctx;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	BIGNUM *x;

	SHA256Init(&sha2ctx);
	SHA256Update(&sha2ctx, salt, strlen(salt));
	SHA256Update(&sha2ctx, PASSWORD, strlen(PASSWORD));
	SHA256Final(hash, &sha2ctx);

	if ((x = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL)) == NULL ||
	    (verifier = BN_new()) == NULL ||
	    BN_mod_exp(verifier, generator, x, modulus, bnctx) == 0)
		goto fail;

	free(x);
	return verifier;
fail:
	return NULL;
}

BIGNUM *
make_public_key(BIGNUM *multiplier, BIGNUM *verifier, BIGNUM *generator, BIGNUM *private_key, BIGNUM *modulus)
{
	BIGNUM *t1, *t2;

	BN_CTX_start(bnctx);

	if ((t1 = BN_CTX_get(bnctx)) == NULL ||
	    BN_mul(t1, multiplier, verifier, bnctx) == 0 ||

	    (t2 = BN_CTX_get(bnctx)) == NULL ||
	    BN_mod_exp(t2, generator, private_key, modulus, bnctx) == 0 ||

	    (public_key = BN_new()) == NULL ||
	    BN_add(public_key, t1, t2) == 0)
		goto fail;

	BN_CTX_end(bnctx);

	return public_key;
fail:
	return NULL;
}

int
main(void)
{
	int listenfd, connfd;
	char *buf, *p;
	size_t i;

	if ((bnctx = BN_CTX_new()) == NULL ||
	    init_params(&modulus, &generator, &multiplier) == 0 ||
	    (salt = make_salt()) == NULL ||
	    (verifier = make_verifier(salt)) == NULL ||
	    (private_key = make_private_key()) == NULL ||
	    (public_key = make_public_key(multiplier, verifier, generator, private_key, modulus)) == NULL ||

	    (listenfd = lo_listen(PORT)) == -1 ||
	    (connfd = accept(listenfd, NULL, NULL)) == -1 ||
	    (buf = srecv(connfd)) == NULL)
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
	    ssendf(connfd, "%s %s", salt, buf) == 0)
		err(1, NULL);

	free(buf);

	if ((scrambler = make_scrambler(client_pubkey, public_key)) == NULL)
		err(1, NULL);

	exit(0);
}
