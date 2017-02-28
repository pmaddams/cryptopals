#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <endian.h>
#include <err.h>
#include <netdb.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "37.h"

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
	SHA2_CTX ctx;
	uint8_t hash[SHA256_DIGEST_LENGTH];

	if ((client->srp = srp_new()) == NULL)
		goto fail;

	client->salt = NULL;

	SHA256Init(&ctx);
	SHA256Final(hash, &ctx);

	memcpy(client->enc_key, hash, KEYSIZE);

	return 1;
fail:
	return 0;
}

int
client_forge_pub_key(struct state *client, uint32_t factor)
{
	BN_CTX *ctx;
	BIGNUM *x;

	factor = htobe32(factor);

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((x = BN_CTX_get(ctx)) == NULL ||
	    BN_bin2bn((uint8_t *) &factor, sizeof(factor), x) == NULL ||
	    BN_mul(client->srp->pub_key, client->srp->n, x, ctx) == 0)
		goto fail;

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

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
get_salt(int connfd, struct state *client)
{
	char *buf;
	ssize_t i;

	if ((buf = srecv(connfd)) == NULL ||

	    (i = strcspn(buf, " ")) > strlen(buf)-2)
		goto fail;
	buf[i] = '\0';

	free(client->salt);
	client->salt = buf;

	free(buf);
	return 1;
fail:
	return 0;
}

int
client_verify_hmac(int connfd, struct state *client)
{
	char *buf, hmac[SHA256_DIGEST_STRING_LENGTH];
	int res;

	generate_hmac(hmac, client);

	if (ssend(connfd, hmac) == 0 ||
	    (buf = srecv(connfd)) == 0)
		goto fail;

	res = strcmp(buf, "OK") == 0;

	free(buf);
	return res;
fail:
	return 0;
}

int
crack_srp(struct state *client, uint32_t factor)
{
	int connfd;

	if (client_forge_pub_key(client, factor) == 0 ||

	    (connfd = lo_connect(PORT)) == 0 ||

	    send_username_and_client_pub_key(connfd, client) == 0 ||
	    get_salt(connfd, client) == 0 ||
	    client_verify_hmac(connfd, client) == 0)
		goto fail;

	return 1;
fail:
	return 0;
}

int
main(void)
{
	struct state client;
	uint32_t factor;

	if (client_init(&client) == 0)
		err(1, NULL);

	for (factor = 0; factor < 3; factor++)
		puts(crack_srp(&client, factor) ? "success" : "failure");

	exit(0);
}
