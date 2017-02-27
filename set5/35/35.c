#include <sys/types.h>

#include <err.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>

#define P	"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"	\
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"	\
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"	\
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"	\
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"	\
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"	\
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"	\
		"fffffffffffff"

#define KEYSIZE	16

struct party {
	DH *dh;
	uint8_t key[KEYSIZE];
	uint8_t iv[KEYSIZE];
	char *message;
};

int
dh_init(struct party *party)
{
	DH *dh;

	if ((dh = DH_new()) == NULL ||
	    (dh->p = BN_new()) == NULL ||
	    (dh->g = BN_new()) == NULL ||

	    BN_hex2bn(&dh->p, P) == 0)
		goto fail;

	party->dh = dh;

	return 1;
fail:
	return 0;
}

int
dh_inject(struct party *party, BIGNUM *g)
{
	return BN_copy(party->dh->g, g) &&

	    DH_generate_key(party->dh);
}

int
dh_exchange(struct party *p1, struct party *p2)
{
	BN_CTX *bnctx;
	BIGNUM *secret;
	size_t len;
	uint8_t *buf,
	    hash[SHA1_DIGEST_LENGTH];
	SHA1_CTX sha1ctx;

	if ((bnctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(bnctx);

	if ((secret = BN_CTX_get(bnctx)) == NULL ||
	    BN_mod_exp(secret, p2->dh->pub_key, p1->dh->priv_key, p1->dh->p, bnctx) == 0)
		goto fail;

	len = BN_num_bytes(secret);
	if ((buf = malloc(len)) == NULL)
		goto fail;

	BN_bn2bin(secret, buf);

	SHA1Init(&sha1ctx);
	SHA1Update(&sha1ctx, buf, len);
	SHA1Final(hash, &sha1ctx);

	memcpy(p1->key, hash, KEYSIZE);
	arc4random_buf(p1->iv, KEYSIZE);

	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);
	free(buf);

	return 1;
fail:
	return 0;
}

int
mitm(struct party *party, BIGNUM *g, struct party *p1, struct party *p2)
{
	BIGNUM *secret;
	size_t len;
	uint8_t *buf,
	    hash[SHA1_DIGEST_LENGTH];
	SHA1_CTX ctx;

	if ((secret = BN_new()) == NULL)
		goto fail;

	if (BN_is_one(g)) {
		if (BN_one(secret) == 0)
			goto fail;
	} else if (BN_cmp(party->dh->p, g) == 0) {
		if (BN_zero(secret) == 0)
			goto fail;
	} else {
		if (p1 == NULL || p2 == NULL)
			goto fail;

		if (BN_cmp(p1->dh->pub_key, BN_value_one()) == 0 ||
		    BN_cmp(p2->dh->pub_key, BN_value_one()) == 0) {
			if (BN_one(secret) == 0)
				goto fail;
		} else
			if (BN_copy(secret, party->dh->p) == NULL ||
			    BN_sub(secret, secret, BN_value_one()) == 0)
				goto fail;
	}

	len = BN_num_bytes(secret);
	if ((buf = malloc(len)) == NULL)
		goto fail;

	BN_bn2bin(secret, buf);

	SHA1Init(&ctx);
	SHA1Update(&ctx, buf, len);
	SHA1Final(hash, &ctx);

	memcpy(party->key, hash, KEYSIZE);

	free(secret);
	free(buf);

	return 1;
fail:
	return 0;
}

int
send_message(struct party *from, struct party *to, char *message)
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

	to->message = buf;

	return 1;
fail:
	return 0;
}

void
put_message(struct party *party)
{
	if (party->message) {
		puts(party->message);
		free(party->message);
		party->message = NULL;
	}
}

int
main(void)
{
	struct party alice, bob, chuck;
	BIGNUM *g;

	if (dh_init(&alice) == 0 ||
	    dh_init(&bob) == 0 ||
	    dh_init(&chuck) == 0 ||

	    (g = BN_new()) == NULL ||
	    BN_one(g) == 0 ||

	    dh_inject(&alice, g) == 0 ||
	    dh_inject(&bob, g) == 0 ||

	    mitm(&chuck, g, NULL, NULL) == 0 ||

	    dh_exchange(&alice, &bob) == 0 ||
	    dh_exchange(&bob, &alice) == 0 ||

	    send_message(&alice, &chuck, "c") == 0)
		err(1, NULL);

	put_message(&chuck);

	if (send_message(&bob, &chuck, "r") == 0)
		err(1, NULL);

	put_message(&chuck);

	if (BN_hex2bn(&g, P) == 0 ||

	    dh_inject(&alice, g) == 0 ||
	    dh_inject(&bob, g) == 0 ||

	    mitm(&chuck, g, NULL, NULL) == 0 ||

	    dh_exchange(&alice, &bob) == 0 ||
	    dh_exchange(&bob, &alice) == 0 ||

	    send_message(&alice, &chuck, "y") == 0)
		err(1, NULL);

	put_message(&chuck);

	if (send_message(&bob, &chuck, "p") == 0)
		err(1, NULL);

	put_message(&chuck);

	if (BN_sub(g, g, BN_value_one()) == 0 ||

	    dh_inject(&alice, g) == 0 ||
	    dh_inject(&bob, g) == 0 ||

	    mitm(&chuck, g, &alice, &bob) == 0 ||

	    dh_exchange(&alice, &bob) == 0 ||
	    dh_exchange(&bob, &alice) == 0 ||

	    send_message(&alice, &chuck, "t") == 0)
		err(1, NULL);

	put_message(&chuck);

	if (send_message(&bob, &chuck, "o") == 0)
		err(1, NULL);

	put_message(&chuck);

	exit(0);
}
