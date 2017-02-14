#include <sys/types.h>

#include <err.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bn.h>

#include "41.h"

struct message {
	time_t timestamp;
	char *text;
};

struct entry {
	time_t timestamp;
	char *hash;
	struct entry *next;
};

struct entry *tab[HASHSIZE];

char *
encrypt_message(struct rsa *rsa, char *text)
{
	struct message msg;
	BIGNUM *in, *out;
	char *res;

	time(&msg.timestamp);
	msg.text = text;

	if ((in = BN_bin2bn((uint8_t *) &msg, sizeof(msg), NULL)) == NULL ||
	    (out = rsa_crypt(rsa, in, ENCRYPT)) == NULL ||
	    (res = BN_bn2hex(out)) == NULL)
		goto fail;

	free(in);
	free(out);

	return res;
fail:
	return NULL;
}

int
check_message(char *enc)
{
	time_t cur;
	char *hash;
	size_t i;
	struct entry *entry, **p, *next;

	if (time(&cur) == -1 ||
	    (hash = SHA256Data(enc, strlen(enc), NULL)) == NULL)
		goto fail;

	i = *(size_t *) hash % HASHSIZE;

	for (entry = tab[i]; entry != NULL;)
		if (cur - entry->timestamp > TIMEOUT) {
			p = &entry;
			next = entry->next;

			free(entry->hash);
			free(entry);

			*p = entry = next;
		} else if (strcmp(hash, entry->hash) == 0) {
			free(hash);
			goto fail;
		} else
			entry = entry->next;

	if ((entry = malloc(sizeof(*entry))) == NULL)
		goto fail;

	entry->timestamp = cur;
	entry->hash = hash;
	entry->next = tab[i];
	tab[i] = entry;

	return 1;
fail:
	return 0;
}

char *
decrypt_message(struct rsa *rsa, char *enc)
{
	BIGNUM *in, *out;
	struct message msg;
	char *res;

	if ((in = BN_new()) == NULL ||
	    BN_hex2bn(&in, enc) == 0 ||
	    (out = rsa_crypt(rsa, in, DECRYPT)) == NULL ||
	    BN_bn2bin(out, (uint8_t *) &msg) == 0 ||
	    (res = strdup(msg.text)) == NULL)
		goto fail;

	free(in);
	free(out);

	return res;
fail:
	return NULL;
}

int
main(int argc, char **argv)
{
	struct rsa rsa;
	char *enc, *dec;

	if (rsa_init(&rsa) == 0 ||
	    (enc = encrypt_message(&rsa, "hello world")) == NULL ||
	    check_message(enc) == 0 ||
	    (dec = decrypt_message(&rsa, enc)) == NULL)
		err(1, NULL);

	puts(dec);

	exit(0);
}
