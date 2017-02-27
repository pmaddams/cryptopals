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

#include "36.h"

#define USERNAME "admin@secure.net"
#define PASSWORD "batman"

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
server_start_init(struct state *server)
{
	struct srp *srp;

	if ((srp = srp_new()) == NULL ||
	    srp_generate_priv_key(srp) == 0)
		goto fail;

	server->srp = srp;

	return 1;
fail:
	return 0;
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
	free(x);

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
server_finish_init(struct state *server)
{
	return generate_verifier(server) && srp_generate_server_pub_key(server->srp);
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

	if (generate_scrambler(server->srp->u, client_pub_key, server->srp->pub_key) == 0 ||

	    (bnctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(bnctx);

	if ((secret = BN_CTX_get(bnctx)) == NULL ||

	    BN_mod_exp(secret, server->srp->v, server->srp->u, server->srp->n, bnctx) == 0 ||
	    BN_mul(secret, client_pub_key, secret, bnctx) == 0 ||
	    BN_mod_exp(secret, secret, server->srp->priv_key, server->srp->n, bnctx) == 0)
		goto fail;

	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);

	len = BN_num_bytes(secret);
	if ((buf = malloc(len)) == NULL ||

	    BN_bn2bin(secret, buf) == 0)
		goto fail;

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
get_username_and_client_pub_key()
{

}

int
send_salt_and_server_pub_key()
{

}

int
main(void)
{
	struct state server;
	int listenfd, connfd;
	BIGNUM *client_pub_key;
	pid_t pid;

	if (server_start_init(&server) == 0)
		err(1, NULL);

	server.username = USERNAME;
	server.password = PASSWORD;
	if ((server.salt = generate_salt()) == NULL ||
	    server_finish_init(&server) == 0 ||
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

		
	}

	/*
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
	*/

	exit(0);
}
