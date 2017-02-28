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
server_init(struct state *server)
{
	struct srp *srp;

	if ((srp = srp_new()) == NULL ||
	    srp_generate_priv_key(srp) == 0)
		goto fail;

	server->srp = srp;

	if (generate_salt(server) == 0 ||

	    srp_generate_priv_key(server->srp) == 0 ||
	    srp_generate_pub_key(server->srp) == 0)
		goto fail;

	return 1;
fail:
	return 0;
}

int
get_client_pub_key(int connfd, struct state *server, BIGNUM **bp)
{
	char *buf, *p;
	size_t i;

	if ((p = buf = srecv(connfd)) == NULL ||
	    (i = strcspn(p, " ")) > strlen(p)-2)
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
crack_password(int connfd, struct state *server, char *path)
{
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

		if (get_client_pub_key(connfd, &server, &client_pub_key) == 0 ||
		    send_salt_and_server_pub_key(connfd, &server) == 0)
			err(1, NULL);

		exit(0);
	}
}
