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

#define BLKSIZ	16

struct party {
	BIGNUM private;
	BIGNUM public;
	BIGNUM shared;

	uint8_t key[BLKSIZ];
	uint8_t iv[BLKSIZ];

	char *msg;
};

BIGNUM *p;

int
dh_params(struct party *party, BIGNUM *g)
{
	BN_CTX *bnctx;
	uint8_t buf[BUFSIZ];

	if ((bnctx = BN_CTX_new()) == NULL)
		goto fail;

	memset(party, 0, sizeof(*party));
	arc4random_buf(buf, BUFSIZ);

	if (BN_bin2bn(buf, BUFSIZ, &party->private) == 0 ||
	    BN_mod_exp(&party->public, g, &party->private, p, bnctx) == 0)
		goto fail;

	BN_CTX_free(bnctx);
	return 1;
fail:
	return 0;
}

int
dh_exchange(struct party *p1, struct party *p2)
{
	BN_CTX *bnctx;

	if ((bnctx = BN_CTX_new()) == NULL ||
	    BN_mod_exp(&p1->shared, &p2->public, &p1->private, p, bnctx) == 0 ||
	    BN_mod_exp(&p2->shared, &p1->public, &p2->private, p, bnctx) == 0)
		goto fail;

	BN_CTX_free(bnctx);
	return 1;
fail:
	return 0;
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
mitm(struct party *party, BIGNUM *g, struct party *p1, struct party *p2)
{
	BN_init(&party->shared);

	if (BN_is_one(g)) {
		if (BN_one(&party->shared) == 0)
			goto fail;
	} else if (BN_cmp(g, p) == 0) {
		if (BN_zero(&party->shared) == 0)
			goto fail;
	} else {
		if (p1 == NULL || p2 == NULL)
			goto fail;

		if (BN_cmp(&p1->public, BN_value_one()) == 0 ||
		    BN_cmp(&p1->public, BN_value_one()) == 0) {
			if (BN_one(&party->shared) == 0)
				goto fail;
		} else
			if (BN_copy(&party->shared, p) == NULL ||
			    BN_sub(&party->shared, &party->shared, BN_value_one()) == 0)
				goto fail;
	}

	return 1;
fail:
	return 0;
}

int
send_msg(struct party *from, struct party *to, char *msg)
{
	BIO *mem, *enc, *dec, *bio_out;
	FILE *memstream;
	char *buf, tmp[BUFSIZ];
	size_t len;
	ssize_t nr;

	if ((mem = BIO_new_mem_buf(msg, strlen(msg))) == NULL ||
	    (enc = BIO_new(BIO_f_cipher())) == NULL ||
	    (dec = BIO_new(BIO_f_cipher())) == NULL ||
	    (memstream = open_memstream(&buf, &len)) == NULL ||
	    (bio_out = BIO_new_fp(memstream, BIO_NOCLOSE)) == NULL)
		goto fail;

	BIO_set_cipher(enc, EVP_aes_128_cbc(), from->key, from->iv, 1);
	BIO_set_cipher(dec, EVP_aes_128_cbc(), to->key, from->iv, 0);
	BIO_push(enc, mem);
	BIO_push(dec, bio_out);

	while ((nr = BIO_read(enc, tmp, BUFSIZ)) > 0)
		if (BIO_write(dec, tmp, nr) < nr)
			goto fail;

	BIO_flush(dec);
	fclose(memstream);
	BIO_free_all(enc);
	BIO_free_all(dec);

	to->msg = buf;

	return 1;
fail:
	return 0;
}

void
put_msg(struct party *party)
{
	if (party->msg) {
		puts(party->msg);
		free(party->msg);
		party->msg = NULL;
	}
}

int
main(void)
{
	BIGNUM *g;
	struct party alice, bob, chuck;

	if ((g = BN_new()) == NULL ||
	    BN_hex2bn(&p, P) == 0)
		err(1, NULL);

	if (BN_one(g) == 0 ||
	    dh_params(&alice, g) == 0 ||
	    dh_params(&bob, g) == 0 ||
	    dh_exchange(&alice, &bob) == 0 ||

	    mitm(&chuck, g, NULL, NULL) == 0 ||

	    enc_params(&alice) == 0 ||
	    enc_params(&bob) == 0 ||
	    enc_params(&chuck) == 0 ||

	    send_msg(&alice, &chuck, "c") == 0)
		err(1, NULL);

	put_msg(&chuck);

	if (send_msg(&bob, &chuck, "r") == 0)
		err(1, NULL);

	put_msg(&chuck);

	if (BN_copy(g, p) == NULL ||
	    dh_params(&alice, g) == 0 ||
	    dh_params(&bob, g) == 0 ||
	    dh_exchange(&alice, &bob) == 0 ||

	    mitm(&chuck, g, NULL, NULL) == 0 ||

	    enc_params(&alice) == 0 ||
	    enc_params(&bob) == 0 ||
	    enc_params(&chuck) == 0 ||

	    send_msg(&alice, &chuck, "y") == 0)
		err(1, NULL);

	put_msg(&chuck);

	if (send_msg(&bob, &chuck, "p") == 0)
		err(1, NULL);

	put_msg(&chuck);

	if (BN_sub(g, g, BN_value_one()) == 0 ||
	    dh_params(&alice, g) == 0 ||
	    dh_params(&bob, g) == 0 ||
	    dh_exchange(&alice, &bob) == 0 ||

	    mitm(&chuck, g, &alice, &bob) == 0 ||

	    enc_params(&alice) == 0 ||
	    enc_params(&bob) == 0 ||
	    enc_params(&chuck) == 0 ||

	    send_msg(&alice, &chuck, "t") == 0)
		err(1, NULL);

	put_msg(&chuck);

	if (send_msg(&bob, &chuck, "o") == 0)
		err(1, NULL);

	put_msg(&chuck);

	exit(0);
}
