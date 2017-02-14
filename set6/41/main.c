#include <sys/types.h>

#include <sha2.h>
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
check_message()
{
}

int
decrypt_message()
{
}

int
main(int argc, char **argv)
{
}
