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

#include "37.h"

BIGNUM *modulus;

char *salt, *shared_k, *hmac;

BN_CTX *bnctx;

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

char *
make_shared_k(void)
{
	if (!shared_k)
		shared_k = SHA256Data("", 0, NULL);

	return shared_k;
}

char *
make_hmac(char *shared_k, char *salt)
{
	char ipad[BLKSIZ], opad[BLKSIZ],
	    hash[SHA256_DIGEST_LENGTH];
	size_t i, len;
	SHA2_CTX sha2ctx;

	if (!hmac) {
		memset(ipad, '\x5c', BLKSIZ);
		memset(opad, '\x36', BLKSIZ);
	
		len = strlen(shared_k);
		for (i = 0; i < len; i++) {
			ipad[i] ^= shared_k[i];
			opad[i] ^= shared_k[i];
		}
	
		SHA256Init(&sha2ctx);
		SHA256Update(&sha2ctx, ipad, BLKSIZ);
		SHA256Update(&sha2ctx, salt, strlen(salt));
		SHA256Final(hash, &sha2ctx);
	
		SHA256Init(&sha2ctx);
		SHA256Update(&sha2ctx, opad, BLKSIZ);
		SHA256Update(&sha2ctx, hash, SHA256_DIGEST_LENGTH);
	
		hmac = SHA256End(&sha2ctx, NULL);
	}

	return hmac;
}

int
crack_srp(uint32_t factor)
{
	BIGNUM *x, *fake_key;
	char *buf;
	int connfd, res;
	size_t i;

	factor = htobe32(factor);

	if ((x = BN_bin2bn((uint8_t *) &factor, sizeof(factor), NULL)) == NULL ||
	    (fake_key = BN_new()) == NULL ||
	    BN_mul(fake_key, modulus, x, bnctx) == 0)
		goto fail;

	if ((buf = BN_bn2hex(fake_key)) == NULL ||

	    (connfd = lo_connect(PORT)) == -1 ||
	    ssendf(connfd, "%s %s", USERNAME, buf) == 0)
		err(1, NULL);

	free(buf);

	if ((salt = srecv(connfd)) == NULL)
		err(1, NULL);

	if ((i = strcspn(salt, " ")) > strlen(salt)-2)
		errx(1, "invalid salt");
	salt[i] = '\0';

	if ((shared_k = make_shared_k()) == NULL ||
	    (hmac = make_hmac(shared_k, salt)) == NULL ||

	    ssend(connfd, hmac) == 0 ||
	    (buf = srecv(connfd)) == NULL)
		err(1, NULL);

	res = strcmp(buf, "OK") == 0;

	BN_free(x);
	BN_free(fake_key);
	close(connfd);
	free(salt);
	free(buf);

	return res;
fail:
	return 0;
}

int
main(void)
{
	uint32_t factor;

	if ((bnctx = BN_CTX_new()) == NULL ||
	    BN_hex2bn(&modulus, N) == 0)
		err(1, NULL);

	for (factor = 0; factor < 3; factor++)
		puts(crack_srp(factor) ? "success" : "failure");

	exit(0);
}
