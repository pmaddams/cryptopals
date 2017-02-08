#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <err.h>
#include <netdb.h>
#include <sha2.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bn.h>

#include "38.h"

BN_CTX *bnctx;

BIGNUM *modulus, *generator, *multiplier,
    *private_key, *public_key, *client_pubkey,
    *scrambler;

char *salt, *client_hmac, *password;

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
make_verifier(BIGNUM *generator, char *salt, char *password, BIGNUM *modulus)
{
	SHA2_CTX sha2ctx;
	char hash[SHA256_DIGEST_LENGTH];
	BIGNUM *verifier, *x;

	SHA256Init(&sha2ctx);
	SHA256Update(&sha2ctx, salt, strlen(salt));
	SHA256Update(&sha2ctx, password, strlen(password));
	SHA256Final(hash, &sha2ctx);

	if ((verifier = BN_new()) == NULL ||
	    (x = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL)) == NULL ||
	    BN_mod_exp(verifier, generator, x, modulus, bnctx) == 0)
		goto fail;

	free(x);
	return verifier;
fail:
	return NULL;
}

BIGNUM *
make_shared_s(BIGNUM *client_pubkey, BIGNUM *verifier, BIGNUM *scrambler, BIGNUM *private_key, BIGNUM *modulus)
{
	BIGNUM *shared_s, *tmp;

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

char *
crack_password(char *client_hmac, char *path)
{
	FILE *fp;
	char *password, *buf, *lbuf, *shared_k, *hmac;
	size_t len;
	BIGNUM *verifier, *shared_s;

	password = NULL;
	if ((fp = fopen(path, "r")) == NULL)
		goto done;

	lbuf = NULL;
	while (buf = fgetln(fp, &len)) {
		if (buf[len-1] == '\n')
			buf[len-1] = '\0';
		else {
			if ((lbuf = malloc(len+1)) == NULL)
				goto done;
			memcpy(lbuf, buf, len);
			lbuf[len] = '\0';
			buf = lbuf;
		}

		if ((verifier = make_verifier(generator, salt, buf, modulus)) == NULL ||
		    (shared_s = make_shared_s(client_pubkey, verifier, scrambler, private_key, modulus)) == NULL ||
		    (shared_k = make_shared_k(shared_s)) == NULL ||
		    (hmac = make_hmac(shared_k, salt)) == NULL)
			goto done;

		if (strcmp(hmac, client_hmac) == 0)
			password = strdup(buf);

		BN_free(verifier);
		BN_free(shared_s);
		free(shared_k);
		free(hmac);

		if (password)
			break;
	}
	free(lbuf);
	fclose(fp);
done:
	return password;
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
		    (buf2 = BN_bn2hex(scrambler)) == NULL ||
		    ssendf(connfd, "%s %s %s", salt, buf, buf2) == 0)
			err(1, NULL);

		free(buf);
		free(buf2);

		if ((client_hmac = srecv(connfd)) == NULL)
			err(1, NULL);

		if ((password = crack_password(client_hmac, DATABASE)) == NULL) {
			if (ssend(connfd, "password not in database") == 0)
				err(1, NULL);
		} else
			if (ssendf(connfd, "your password was \"%s\"", password) == 0)
				err(1, NULL);

		break;
	}

	exit(0);
}
