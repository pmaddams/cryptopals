#include <sys/types.h>

#include <ctype.h>
#include <err.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/dsa.h>

#define FILENAME	"DATA"

#define P		"800000000000000089e1855218a0e7dac38136ffafa72eda7"	\
			"859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"	\
			"2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"	\
			"ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"	\
			"b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"	\
			"1a584471bb1"

#define Q		"f4f47f05794b256174bba6e9b396a7707e563c5b"

#define G		"5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"	\
			"458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"	\
			"322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"	\
			"0f5b64c36b625a097f1651fe775323556fe00b3608c887892"	\
			"878480e99041be601a62166ca6894bdd41a7054ec89f756ba"	\
			"9fc95302291"

#define PUB_KEY		"2d026f4bf30195ede3a088da85e398ef869611d0f68f07"	\
			"13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"	\
			"5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"	\
			"f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"	\
			"f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"	\
			"2971c3de5084cce04a2e147821"

struct entry {
	BIGNUM *m;
	DSA_SIG *sig;
};

struct data {
	struct entry **entries;
	size_t len;
};

struct entry *
new_entry(char *s_buf, char *r_buf, char *m_buf)
{
	struct entry *entry;
	size_t i;

	if ((entry = malloc(sizeof(*entry))) == NULL ||
	    (entry->m = BN_new()) == NULL ||
	    (entry->sig = DSA_SIG_new()) == NULL)
		goto fail;

	if ((i = strcspn(m_buf, " ")) > strlen(m_buf)-2)
		goto fail;
	m_buf += i+1;
	m_buf[strcspn(m_buf, "\n")] = '\0';

	if (BN_hex2bn(&entry->m, m_buf) == 0)
		goto fail;

	if ((i = strcspn(s_buf, " ")) > strlen(s_buf)-2)
		goto fail;
	s_buf += i+1;
	s_buf[strcspn(s_buf, "\n")] = '\0';

	if (BN_dec2bn(&entry->sig->s, s_buf) == 0)
		goto fail;

	if ((i = strcspn(r_buf, " ")) > strlen(r_buf)-2)
		goto fail;
	r_buf += i+1;
	r_buf[strcspn(r_buf, "\n")] = '\0';

	if (BN_dec2bn(&entry->sig->r, r_buf) == 0)
		goto fail;

	return entry;
fail:
	return NULL;
}

int
load_data(struct data *data, FILE *fp)
{
	char *msg_buf, *s_buf, *r_buf, *m_buf;
	size_t msg_size, s_size, r_size, m_size;
	ssize_t len;
	struct entry *entry, **newp;

	data->entries = NULL;
	data->len = 0;

	msg_buf = s_buf = r_buf = m_buf = NULL;
	msg_size = s_size = r_size = m_size = 0;

	for (;;) {
		if (getline(&msg_buf, &msg_size, fp) == -1 ||
		    getline(&s_buf, &s_size, fp) == -1 ||
		    getline(&r_buf, &r_size, fp) == -1 ||
		    getline(&m_buf, &m_size, fp) == -1)
			break;

		if ((entry = new_entry(s_buf, r_buf, m_buf)) == NULL ||
		    (newp = reallocarray(data->entries, data->len+1, sizeof(*data->entries))) == NULL)
			goto fail;

		data->entries = newp;
		data->entries[data->len++] = entry;
	}

	if (ferror(fp))
		goto fail;

	free(msg_buf);
	free(s_buf);
	free(r_buf);
	free(m_buf);

	return 1;
fail:
	return 0;
}

int
crack_possible_k(BIGNUM *res, DSA *dsa, struct entry *e1, struct entry *e2, BN_CTX *ctx)
{
	BIGNUM *t1, *t2;

	if ((t1 = BN_CTX_get(ctx)) == NULL ||
	    (t2 = BN_CTX_get(ctx)) == NULL ||

	    BN_mod_sub(t1, e1->m, e2->m, dsa->q, ctx) == 0 ||
	    BN_mod_sub(t2, e1->sig->s, e2->sig->s, dsa->q, ctx) == 0 ||
	    BN_mod_inverse(t2, t2, dsa->q, ctx) == 0 ||
	    BN_mod_mul(res, t1, t2, dsa->q, ctx) == 0)
		goto fail;

	return 1;
fail:
	return 0;
}

int
crack_possible_priv_key(BIGNUM *res, DSA *dsa, struct entry *entry, BIGNUM *k, BN_CTX *ctx)
{
	BIGNUM *tmp;

	if ((tmp = BN_CTX_get(ctx)) == NULL ||

	    BN_mod_mul(res, entry->sig->s, k, dsa->q, ctx) == 0 ||
	    BN_mod_sub(res, res, entry->m, dsa->q, ctx) == 0 ||
	    BN_mod_inverse(tmp, entry->sig->r, dsa->q, ctx) == 0 ||
	    BN_mod_mul(res, res, tmp, dsa->q, ctx) == 0)
		goto fail;

	return 1;
fail:
	return 0;
}

int
crack_dsa(DSA *dsa, struct data *data)
{
	BN_CTX *ctx;
	BIGNUM *k, *priv_key, *pub_key;
	size_t i, j;
	struct entry *e1, *e2;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((k = BN_CTX_get(ctx)) == NULL ||
	    (priv_key = BN_CTX_get(ctx)) == NULL ||
	    (pub_key = BN_CTX_get(ctx)) == NULL)
		goto fail;

	for (i = 0; i < data->len-1; i++) {
		e1 = data->entries[i];

		for (j = i+1; j < data->len; j++) {
			e2 = data->entries[j];

			if (crack_possible_k(k, dsa, e1, e2, ctx) == 0 ||
			    crack_possible_priv_key(priv_key, dsa, e1, k, ctx) == 0 ||
			    BN_mod_exp(pub_key, dsa->g, priv_key, dsa->p, ctx) == 0)
				goto fail;

			if (BN_cmp(pub_key, dsa->pub_key) == 0) {
				if (BN_copy(dsa->priv_key, priv_key) == 0)
					goto fail;

				goto done;
			}
		}
	}
fail:
	return 0;
done:
	return 1;
}

int
main(void)
{
	DSA *dsa;
	FILE *fp;
	struct data data;
	char *buf;
	size_t i, len;

	if ((dsa = DSA_new()) == NULL ||

	    BN_hex2bn(&dsa->p, P) == 0 ||
	    BN_hex2bn(&dsa->q, Q) == 0 ||
	    BN_hex2bn(&dsa->g, G) == 0 ||
	    BN_hex2bn(&dsa->pub_key, PUB_KEY) == 0 ||

	    (dsa->priv_key = BN_new()) == NULL ||

	    (fp = fopen(FILENAME, "r")) == NULL ||
	    load_data(&data, fp) == 0 ||

	    crack_dsa(dsa, &data) == 0 ||

	    (buf = BN_bn2hex(dsa->priv_key)) == NULL)
		err(1, NULL);

	len = strlen(buf);
	for (i = 0; i < len; i++)
		buf[i] = tolower(buf[i]);

	puts(buf);

	exit(0);
}
