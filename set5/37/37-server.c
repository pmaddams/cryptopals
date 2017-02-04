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

#include "37.h"

#define N	"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"	\
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"	\
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"	\
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"	\
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"	\
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"	\
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"	\
		"fffffffffffff"
#define G	"2"
#define K	"3"

BN_CTX *bnctx;

BIGNUM *modulus, *generator, *multiplier, *verifier,
    *private_key, *public_key, *client_pubkey,
    *scrambler, *shared_s;

char *salt, *shared_k, *hmac;

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
init_params(BIGNUM **modp, BIGNUM **genp, BIGNUM **mulp)
{
	return BN_hex2bn(modp, N) &&
	    BN_hex2bn(genp, G) &&
	    BN_hex2bn(mulp, K);
}

char *
atox(uint8_t *src, size_t srclen)
{
	size_t i, j;
	char *dst;

	if ((dst = malloc(srclen*2+1)) == NULL)
		goto done;

	for (i = j = 0; i < srclen; i++, j += 2)
		snprintf(dst+j, 3, "%02x", src[i]);
done:
	return dst;
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
	uint8_t hash[SHA256_DIGEST_LENGTH],
	    password[SHA256_DIGEST_STRING_LENGTH];
	BIGNUM *x;

	arc4random_buf(password, SHA256_DIGEST_STRING_LENGTH);

	SHA256Init(&sha2ctx);
	SHA256Update(&sha2ctx, salt, strlen(salt));
	SHA256Update(&sha2ctx, password, SHA256_DIGEST_STRING_LENGTH);
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
make_private_key(void)
{
	char buf[BUFSIZ];

	arc4random_buf(buf, BUFSIZ);

	return BN_bin2bn(buf, BUFSIZ, NULL);
}

BIGNUM *
make_public_key(BIGNUM *multiplier, BIGNUM *verifier, BIGNUM *generator, BIGNUM *private_key, BIGNUM *modulus)
{
	BIGNUM *t1, *t2;

	BN_CTX_start(bnctx);

	if ((public_key = BN_new()) == NULL ||
	    (t1 = BN_CTX_get(bnctx)) == NULL ||
	    (t2 = BN_CTX_get(bnctx)) == NULL ||

	    BN_mul(t1, multiplier, verifier, bnctx) == 0 ||
	    BN_mod_exp(t2, generator, private_key, modulus, bnctx) == 0 ||
	    BN_add(public_key, t1, t2) == 0)
		goto fail;

	BN_CTX_end(bnctx);

	return public_key;
fail:
	return NULL;
}

BIGNUM *
make_scrambler(BIGNUM *server_pubkey)
{
	SHA2_CTX sha2ctx;
	size_t len;
	char *buf, hash[SHA256_DIGEST_LENGTH];

	SHA256Init(&sha2ctx);

	SHA256Update(&sha2ctx, "", 0);

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
	BIGNUM *tmp;

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

	if ((scrambler = make_scrambler(public_key)) == NULL ||
	    (shared_s = make_shared_s(client_pubkey, verifier, scrambler, private_key, modulus)) == NULL ||
	    (shared_k = make_shared_k(shared_s)) == NULL ||
	    (hmac = make_hmac(shared_k, salt)) == NULL ||

	    (buf = srecv(connfd)) == NULL ||
	    ssend(connfd, strcmp(buf, hmac) == 0 ? "OK" : "NO") == 0)
		errx(1, "debug");

	sleep(1);
	exit(0);
}
