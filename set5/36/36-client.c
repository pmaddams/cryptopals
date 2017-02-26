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

#include "36.h"

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
client_init(struct state *client)
{
	struct srp *srp;

	if ((srp = srp_new()) == NULL)
		goto fail;
}

BIGNUM *
make_public_key(BIGNUM *generator, BIGNUM *private_key, BIGNUM *modulus)
{
	BN_CTX *bnctx;

	if ((bnctx = BN_CTX_new()) == NULL ||
	    (public_key = BN_new()) == NULL ||
	    BN_mod_exp(public_key, generator, private_key, modulus, bnctx) == 0)
		goto fail;

	BN_CTX_free(bnctx);
	return public_key;
fail:
	return NULL;
}

BIGNUM *
make_shared_s(char *salt, char *password, BIGNUM *server_pubkey, BIGNUM *multiplier, BIGNUM *generator, BIGNUM *private_key, BIGNUM *scrambler, BIGNUM *modulus)
{
	BN_CTX *bnctx;
	SHA2_CTX sha2ctx;
	char hash[SHA256_DIGEST_LENGTH];
	BIGNUM *x, *t1, *t2;

	if ((bnctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(bnctx);

	SHA256Init(&sha2ctx);
	SHA256Update(&sha2ctx, salt, strlen(salt));
	SHA256Update(&sha2ctx, password, strlen(password));
	SHA256Final(hash, &sha2ctx);

	if ((shared_s = BN_new()) == NULL ||
	    (x = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL)) == NULL ||
	    (t1 = BN_CTX_get(bnctx)) == NULL ||
	    (t2 = BN_CTX_get(bnctx)) == NULL ||

	    BN_mod_exp(t1, generator, x, modulus, bnctx) == 0 ||
	    BN_mul(t1, multiplier, t1, bnctx) == 0 ||
	    BN_sub(t1, server_pubkey, t1) == 0 ||
	    BN_mul(t2, scrambler, x, bnctx) == 0 ||
	    BN_add(t2, private_key, t2) == 0 ||
	    BN_mod_exp(shared_s, t1, t2, modulus, bnctx) == 0)
		goto fail;

	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);
	free(x);

	return shared_s;
fail:
	return NULL;
}

int
main(void)
{
	int connfd;
	char *buf, *p;
	size_t i;

	if (init_params(&modulus, &generator, &multiplier) == 0 ||
	    (private_key = make_private_key()) == NULL ||
	    (public_key = make_public_key(generator, private_key, modulus)) == NULL)
		err(1, NULL);

	print("username: ");
	if ((username = input()) == NULL ||
	    (buf = BN_bn2hex(public_key)) == NULL ||

	    (connfd = lo_connect(PORT)) == -1 ||
	    ssendf(connfd, "%s %s", username, buf) == 0)
		err(1, NULL);

	free(buf);

	if ((buf = srecv(connfd)) == NULL)
		err(1, NULL);

	p = buf;
	if ((i = strcspn(p, " ")) > strlen(p)-2)
		errx(1, "invalid salt");
	p[i] = '\0';

	if ((salt = strdup(p)) == NULL)
		err(1, NULL);

	p += i+1;
	if ((server_pubkey = BN_new()) == NULL ||
	    BN_hex2bn(&server_pubkey, p) == 0)
		err(1, NULL);

	free(buf);

	if ((scrambler = make_scrambler(public_key, server_pubkey)) == NULL)
		err(1, NULL);

	print("password: ");
	if ((password = input()) == NULL ||
	    (shared_s = make_shared_s(salt, password, server_pubkey, multiplier, generator, private_key, scrambler, modulus)) == NULL ||
	    (shared_k = make_shared_k(shared_s)) == NULL ||
	    (hmac = make_hmac(shared_k, salt)) == NULL ||

	    ssend(connfd, hmac) == 0 ||
	    (buf = srecv(connfd)) == NULL)
		err(1, NULL);

	puts(strcmp(buf, "OK") == 0 ? "success" : "failure");

	exit(0);
}
