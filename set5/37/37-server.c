#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <err.h>
#include <netdb.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bn.h>

#include "37.h"

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
atox(uint8_t *buf, size_t len)
{
	size_t i, j;
	char *res;

	if ((res = malloc(len*2+1)) == NULL)
		goto done;

	for (i = j = 0; i < len; i++, j += 2)
		snprintf(res+j, 3, "%02x", buf[i]);
done:
	return res;
}

char *
generate_salt(void)
{
	uint32_t num;

	num = arc4random();
	return atox((uint8_t *) &num, sizeof(num));
}

int
generate_verifier(struct state *server)
{
	BN_CTX *bnctx;
	SHA2_CTX sha2ctx;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	BIGNUM *x;

	if ((bnctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(bnctx);

	SHA256Init(&sha2ctx);
	SHA256Update(&sha2ctx, server->salt, strlen(server->salt));
	SHA256Update(&sha2ctx, server->password, strlen(server->password));
	SHA256Final(hash, &sha2ctx);

	if ((x = BN_CTX_get(bnctx)) == NULL ||
	    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, x) == NULL ||
	    BN_mod_exp(server->srp->v, server->srp->g, x, server->srp->n, bnctx) == 0)
		goto fail;

	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);

	return 1;
fail:
	return 0;
}

int
srp_generate_server_priv_key(struct srp *srp)
{
	do
		if (BN_rand_range(srp->priv_key, srp->n) == 0)
			goto fail;
	while (BN_is_zero(srp->priv_key));

	return 1;
fail:
	return 0;
}

int
srp_generate_server_pub_key(struct srp *srp)
{
	BN_CTX *bnctx;
	BIGNUM *t1, *t2;

	if ((bnctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(bnctx);

	if ((t1 = BN_CTX_get(bnctx)) == NULL ||
	    (t2 = BN_CTX_get(bnctx)) == NULL ||

	    BN_mul(t1, srp->k, srp->v, bnctx) == 0 ||
	    BN_mod_exp(t2, srp->g, srp->priv_key, srp->n, bnctx) == 0 ||
	    BN_add(srp->pub_key, t1, t2) == 0)
		goto fail;

	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);

	return 1;
fail:
	return 0;
}

int
server_init(struct state *server)
{
	struct srp *srp;

	if ((srp = srp_new()) == NULL)
		goto fail;

	server->username = USERNAME;

	if ((server->password = malloc(KEYSIZE)) == NULL)
		goto fail;
	arc4random_buf(server->password, KEYSIZE);

	if ((server->salt = generate_salt()) == NULL ||

	    generate_verifier(server) == 0 ||

	    srp_generate_server_priv_key(server->srp) == 0 ||
	    srp_generate_server_pub_key(server->srp) == 0)
		goto fail;

	return 1;
fail:
	return 0;
}

/*
BIGNUM *
make_scrambler(BIGNUM *client_pubkey, BIGNUM *server_pubkey)
{
	SHA2_CTX sha2ctx;
	size_t len;
	char *buf, hash[SHA256_DIGEST_LENGTH];

	SHA256Init(&sha2ctx);

	len = BN_num_bytes(client_pubkey);
	if ((buf = malloc(len+1)) == NULL)
		goto fail;

	BN_bn2bin(client_pubkey, buf);

	SHA256Update(&sha2ctx, buf, len);
	free(buf);

	len = BN_num_bytes(server_pubkey);
	if ((buf = malloc(len)) == NULL ||
	    BN_bn2bin(server_pubkey, buf) == 0)
		goto fail;

	SHA256Update(&sha2ctx, buf, len);
	free(buf);

	SHA256Final(hash, &sha2ctx);

	return BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);
fail:
	return NULL;
}

BIGNUM *
make_shared_s(BIGNUM *client_pubkey, BIGNUM *verifier, BIGNUM *scrambler, BIGNUM *private_key, BIGNUM *modulus)
{
	BN_CTX *bnctx;
	BIGNUM *tmp;

	if ((bnctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(bnctx);

	if ((shared_s = BN_new()) == NULL ||
	    (tmp = BN_CTX_get(bnctx)) == NULL ||

	    BN_mod_exp(tmp, verifier, scrambler, modulus, bnctx) == 0 ||
	    BN_mul(tmp, client_pubkey, tmp, bnctx) == 0 ||
	    BN_mod_exp(shared_s, tmp, private_key, modulus, bnctx) == 0)
		goto fail;

	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);

	return shared_s;
fail:
	return NULL;
}

char *
make_shared_k(BIGNUM *shared_s)
{
	size_t len;
	char *buf, *res;

	len = BN_num_bytes(shared_s);
	if ((buf = malloc(len+1)) == NULL)
		goto fail;

	BN_bn2bin(shared_s, buf);

	if ((res = SHA256Data(buf, len, NULL)) == NULL)
		goto fail;

	free(buf);
	return res;
fail:
	return NULL;
}

int
main(void)
{
	int listenfd, connfd;
	pid_t pid;
	char *buf, *p;
	size_t i;

	if (init_params(&modulus, &generator, &multiplier) == 0 ||
	    (salt = make_salt()) == NULL ||
	    (verifier = make_verifier(salt)) == NULL ||
	    (private_key = make_private_key()) == NULL ||
	    (public_key = make_public_key(multiplier, verifier, generator, private_key, modulus)) == NULL ||
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
		if ((i = strcspn(p, " ")) > strlen(p)-2)
			errx(1, "invalid username");
		p[i] = '\0';
		if (strcmp(p, USERNAME) != 0)
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

		if ((scrambler = make_scrambler(client_pubkey, public_key)) == NULL ||
		    (shared_s = make_shared_s(client_pubkey, verifier, scrambler, private_key, modulus)) == NULL ||
		    (shared_k = make_shared_k(shared_s)) == NULL ||
		    (hmac = make_hmac(shared_k, salt)) == NULL ||

		    (buf = srecv(connfd)) == NULL ||
		    ssend(connfd, strcmp(buf, hmac) == 0 ? "OK" : "NO") == 0)
			err(1, NULL);

		break;
	}

	exit(0);
}
*/

int
main(void)
{
	return 0;
}
