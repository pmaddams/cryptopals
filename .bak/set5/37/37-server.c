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

int
generate_salt(struct state *server)
{
	uint32_t num;

	num = arc4random();

	return (server->salt = atox((uint8_t *) &num, sizeof(num))) != NULL;
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
	SHA256Update(&sha2ctx, server->password, KEYSIZE);
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
	if ((server->srp = srp_new()) == NULL)
		goto fail;

	server->username = USERNAME;
	if ((server->password = malloc(KEYSIZE)) == NULL)
		goto fail;
	arc4random_buf(server->password, KEYSIZE);

	if (generate_salt(server) == 0 ||
	    generate_verifier(server) == 0 ||

	    srp_generate_server_priv_key(server->srp) == 0 ||
	    srp_generate_server_pub_key(server->srp) == 0)
		goto fail;

	return 1;
fail:
	return 0;
}

int
get_username_and_client_pub_key(int connfd, struct state *server, BIGNUM **bp)
{
	char *buf, *p;
	size_t i;

	if ((p = buf = srecv(connfd)) == NULL ||
	    (i = strcspn(p, " ")) > strlen(p)-2)
		goto fail;

	p[i] = '\0';
	if (strcmp(p, server->username) != 0)
		goto fail;

	p += i+1;
	if (BN_hex2bn(bp, p) == 0)
		goto fail;

	free(buf);
	return 1;
fail:
	return 0;
}

int
send_salt_and_server_pub_key(int connfd, struct state *server)
{
	char *buf;

	if ((buf = BN_bn2hex(server->srp->pub_key)) == NULL ||
	    ssendf(connfd, "%s %s", server->salt, buf) == 0)

	free(buf);
	return 1;
fail:
	return 0;
}

int
generate_scrambler(struct state *server, BIGNUM *client_pub_key)
{
	SHA2_CTX sha2ctx;
	size_t len;
	char *buf, hash[SHA256_DIGEST_LENGTH];

	SHA256Init(&sha2ctx);

	len = BN_num_bytes(client_pub_key);
	if ((buf = malloc(len)) == NULL)
		goto fail;

	BN_bn2bin(client_pub_key, buf);

	SHA256Update(&sha2ctx, buf, len);
	free(buf);

	len = BN_num_bytes(server->srp->pub_key);
	if ((buf = malloc(len)) == NULL)
		goto fail;

	BN_bn2bin(server->srp->pub_key, buf);

	SHA256Update(&sha2ctx, buf, len);
	free(buf);

	SHA256Final(hash, &sha2ctx);

	return BN_bin2bn(hash, SHA256_DIGEST_LENGTH, server->srp->u) != NULL;
fail:
	return 0;
}

int
server_generate_enc_key(struct state *server, BIGNUM *client_pub_key)
{
	BN_CTX *bnctx;
	BIGNUM *secret;
	size_t len;
	uint8_t *buf,
	    hash[SHA256_DIGEST_LENGTH];
	SHA2_CTX sha2ctx;

	if (generate_scrambler(server, client_pub_key) == 0 ||

	    (bnctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(bnctx);

	if ((secret = BN_CTX_get(bnctx)) == NULL ||

	    BN_mod_exp(secret, server->srp->v, server->srp->u, server->srp->n, bnctx) == 0 ||
	    BN_mul(secret, client_pub_key, secret, bnctx) == 0 ||
	    BN_mod_exp(secret, secret, server->srp->priv_key, server->srp->n, bnctx) == 0)
		goto fail;

	len = BN_num_bytes(secret);
	if ((buf = malloc(len)) == NULL)
		goto fail;

	BN_bn2bin(secret, buf);

	SHA256Init(&sha2ctx);
	SHA256Update(&sha2ctx, buf, len);
	SHA256Final(hash, &sha2ctx);

	memcpy(server->enc_key, hash, KEYSIZE);

	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);
	free(buf);

	return 1;
fail:
	return 0;
}

int
server_verify_hmac(int connfd, struct state *server)
{
	char *buf, hmac[SHA256_DIGEST_STRING_LENGTH];

	generate_hmac(hmac, server);

	if ((buf = srecv(connfd)) == NULL ||
	    ssend(connfd, strcmp(buf, hmac) == 0 ? "OK" : "NO") == 0)
		goto fail;

	free(buf);
	return 1;
fail:
	return 0;
}

int
main(void)
{
	struct state server;
	int listenfd, connfd;
	BIGNUM *client_pub_key;
	pid_t pid;

	if (server_init(&server) == 0 ||
	    (listenfd = lo_listen(PORT)) == 0 ||
	    (client_pub_key = BN_new()) == NULL)
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

		if (get_username_and_client_pub_key(connfd, &server, &client_pub_key) == 0 ||
		    send_salt_and_server_pub_key(connfd, &server) == 0 ||
		    server_generate_enc_key(&server, client_pub_key) == 0 ||
		    server_verify_hmac(connfd, &server) == 0)
			err(1, NULL);

		exit(0);
	}
}
