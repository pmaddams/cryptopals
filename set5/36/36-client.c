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
srp_generate_client_pub_key(struct srp *srp)
{
	BN_CTX *ctx;

	if ((ctx = BN_CTX_new()) == NULL ||
	    BN_mod_exp(srp->pub_key, srp->g, srp->priv_key, srp->n, ctx) == 0)
		goto fail;

	BN_CTX_free(ctx);
	return 1;
fail:
	return 0;
}

int
client_init(struct state *client)
{
	struct srp *srp;

	if ((srp = srp_new()) == NULL ||
	    srp_generate_priv_key(srp) == 0 ||
	    srp_generate_client_pub_key(srp) == 0)
		goto fail;

	client->srp = srp;

	return 1;
fail:
	return 0;
}

int
client_generate_enc_key(struct state *client, BIGNUM *server_pub_key)
{
	BN_CTX *bnctx;
	SHA2_CTX sha2ctx;
	char hash[SHA256_DIGEST_LENGTH];
	BIGNUM *secret, *x, *t1, *t2;
	size_t len;
	char *buf;

	if (generate_scrambler(client->srp->u, client->srp->pub_key, server_pub_key) == 0 ||

	    (bnctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(bnctx);

	SHA256Init(&sha2ctx);
	SHA256Update(&sha2ctx, client->salt, strlen(client->salt));
	SHA256Update(&sha2ctx, client->password, strlen(client->password));
	SHA256Final(hash, &sha2ctx);

	if ((secret = BN_new()) == NULL ||
	    (x = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL)) == NULL ||
	    (t1 = BN_CTX_get(bnctx)) == NULL ||
	    (t2 = BN_CTX_get(bnctx)) == NULL ||

	    BN_mod_exp(t1, client->srp->g, x, client->srp->n, bnctx) == 0 ||
	    BN_mul(t1, client->srp->k, t1, bnctx) == 0 ||
	    BN_sub(t1, server_pub_key, t1) == 0 ||
	    BN_mul(t2, client->srp->u, x, bnctx) == 0 ||
	    BN_add(t2, client->srp->priv_key, t2) == 0 ||
	    BN_mod_exp(secret, t1, t2, client->srp->n, bnctx) == 0)
		goto fail;

	len = BN_num_bytes(secret);
	if ((buf = malloc(len)) == NULL ||

	    BN_bn2bin(secret, buf) == 0)
		goto fail;

	SHA256Init(&sha2ctx);
	SHA256Update(&sha2ctx, buf, len);
	SHA256Final(hash, &sha2ctx);

	memcpy(client->enc_key, hash, KEYSIZE);

	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);
	free(buf);

	return 1;
fail:
	return 0;
}

int
send_username_and_client_pub_key(int connfd, struct state *client)
{
	char *buf;

	if ((buf = BN_bn2hex(client->srp->pub_key)) == NULL ||
	    ssendf(connfd, "%s %s", client->username, buf) == 0)
		goto fail;

	free(buf);
	return 1;
fail:
	return 0;
}

int
get_salt_and_server_pub_key(int connfd, struct state *client, BIGNUM **bp)
{
	char *buf, *p;
	ssize_t i;

	if ((p = buf = srecv(connfd)) == NULL)
		goto fail;

	if ((i = strcspn(p, " ")) > strlen(p)-2)
		goto fail;
	p[i] = '\0';

	if ((client->salt = strdup(p)) == NULL)
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
client_verify_hmac(int connfd, struct state *client)
{
	char hmac[SHA256_DIGEST_STRING_LENGTH],
	    *buf;
	int res;

	generate_hmac(client, hmac);

	if (ssend(connfd, hmac) == 0 ||
	    (buf = srecv(connfd)) == 0)
		goto fail;

	res = strcmp(hmac, buf) == 0;

	free(buf);
	return res;
fail:
	return 0;
}

int
main(void)
{
	struct state client;
	int connfd;
	BIGNUM *server_pub_key;

	if (client_init(&client) == 0 ||
	    (connfd = lo_connect(PORT)) == -1 ||
	    (server_pub_key = BN_new()) == NULL)
		err(1, NULL);

	print("username: ");
	if ((client.username = input()) == NULL)
		err(1, NULL);

	print("password: ");
	if ((client.password = input()) == NULL)
		err(1, NULL);

	if (send_username_and_client_pub_key(connfd, &client) == 0 ||

	    get_salt_and_server_pub_key(connfd, &client, &server_pub_key) == 0 ||

	    client_generate_enc_key(&client, server_pub_key) == 0)
		err(1, NULL);

	puts(client_verify_hmac(connfd, &client) ? "success" : "failure");

	exit(0);
}
