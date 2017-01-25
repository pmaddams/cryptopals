#include <sys/types.h>

#include <err.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#define P	"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"	\
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"	\
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"	\
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"	\
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"	\
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"	\
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"	\
		"fffffffffffff"
#define G	"2"

#define BLKSIZ	16

struct party {
	BIGNUM private;
	BIGNUM public;
	BIGNUM shared;

	uint8_t key[BLKSIZ];
	uint8_t iv[BLKSIZ];

	char *message;
};

BIGNUM *p;
BN_CTX *bnctx;

int
dh_params(struct party *party, BIGNUM *g)
{
	uint8_t buf[BUFSIZ];

	memset(party, 0, sizeof(*party));
	arc4random_buf(buf, BUFSIZ);

	return BN_bin2bn(buf, BUFSIZ, &party->private) &&
	    BN_mod_exp(&party->public, g, &party->private, p, bnctx);
}

int
dh_xchg(struct party *p1, struct party *p2)
{
	return BN_mod_exp(&p1->shared, &p2->public, &p1->private, p, bnctx) &&
	    BN_mod_exp(&p2->shared, &p1->public, &p2->private, p, bnctx);
}

int
enc_params(struct party *party)
{
	size_t len;
	uint8_t *buf, hash[SHA1_DIGEST_LENGTH];
	SHA1_CTX sha1ctx;

	len = BN_num_bytes(&party->shared);

	if ((buf = malloc(len)) == NULL)
		goto fail;

	BN_bn2bin(&party->shared, buf);

	SHA1Init(&sha1ctx);
	SHA1Update(&sha1ctx, buf, len);
	SHA1Final(hash, &sha1ctx);

	memcpy(party->key, hash, BLKSIZ);
	arc4random_buf(party->iv, BLKSIZ);

	free(buf);
	return 1;
fail:
	return 0;
}

int
mitm(struct party *m, BIGNUM *g)
{
	BN_init(&m->shared);

	if (BN_is_one(g)) {
		if (BN_one(&m->shared) == 0)
			goto fail;
	} else if (BN_cmp(g, p) == 0) {
		if (BN_zero(&m->shared) == 0)
			goto fail;
	}

	return 1;
fail:
	return 0;
}

int
send_msg(struct party *send, struct party *recv, char *message)
{
	BIO *mem, *enc, *dec, *bio_out;
	FILE *memstream;
	char *buf, tmp[BUFSIZ];
	size_t len;
	ssize_t nr;

	if ((mem = BIO_new_mem_buf(message, strlen(message))) == NULL ||
	    (enc = BIO_new(BIO_f_cipher())) == NULL ||
	    (dec = BIO_new(BIO_f_cipher())) == NULL ||
	    (memstream = open_memstream(&buf, &len)) == NULL ||
	    (bio_out = BIO_new_fp(memstream, BIO_NOCLOSE)) == NULL)
		goto fail;

	BIO_set_cipher(enc, EVP_aes_128_cbc(), send->key, send->iv, 1);
	BIO_set_cipher(dec, EVP_aes_128_cbc(), recv->key, send->iv, 0);
	BIO_push(enc, mem);
	BIO_push(dec, bio_out);

	while ((nr = BIO_read(enc, tmp, BUFSIZ)) > 0)
		if (BIO_write(dec, tmp, nr) < nr)
			goto fail;

	BIO_flush(dec);
	fclose(memstream);
	BIO_free_all(enc);
	BIO_free_all(dec);

	recv->message = buf;

	return 1;
fail:
	return 0;
}

void
write_msg(struct party *party)
{
	puts(party->message);
	free(party->message);
}

int
main(void)
{
	BIGNUM *g;
	struct party alice, bob, chuck;

	if ((bnctx = BN_CTX_new()) == NULL ||
	    BN_hex2bn(&p, P) == 0 ||
	    (g = BN_new()) == NULL)
		err(1, NULL);

	BN_init(g);

	if (BN_one(g) == 0 ||
	    dh_params(&alice, g) == 0 ||
	    dh_params(&bob, g) == 0 ||

	    dh_xchg(&alice, &bob) == 0 ||

	    mitm(&chuck, g) == 0 ||

	    enc_params(&alice) == 0 ||
	    enc_params(&bob) == 0 ||
	    enc_params(&chuck) == 0 ||

	    send_msg(&alice, &chuck, "c") == 0)
		err(1, NULL);

	write_msg(&chuck);

	if (send_msg(&bob, &chuck, "r") == 0)
		err(1, NULL);

	write_msg(&chuck);

	if (BN_copy(g, p) == 0 ||
	    dh_params(&alice, g) == 0 ||
	    dh_params(&bob, g) == 0 ||

	    dh_xchg(&alice, &bob) == 0 ||

	    mitm(&chuck, g) == 0 ||

	    enc_params(&alice) == 0 ||
	    enc_params(&bob) == 0 ||
	    enc_params(&chuck) == 0 ||

	    send_msg(&alice, &chuck, "y") == 0)
		err(1, NULL);

	write_msg(&chuck);

	if (send_msg(&bob, &chuck, "p") == 0)
		err(1, NULL);

	write_msg(&chuck);

	exit(0);
}
