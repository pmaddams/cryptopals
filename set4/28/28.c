#include <sys/types.h>

#include <err.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLKSIZ 64

uint8_t *
sha1_hash(uint8_t *buf, size_t len)
{
	uint8_t *res;
	SHA1_CTX sha;

	if ((res = malloc(SHA1_DIGEST_LENGTH)) == NULL)
		goto done;

	SHA1Init(&sha);
	SHA1Update(&sha, (u_int8_t *) buf, len);
	SHA1Final((u_int8_t *) res, &sha);
done:
	return res;
}

uint8_t *
sha1_mac(uint8_t *key, size_t keylen, char *message)
{
	size_t msglen;
	uint8_t *buf, *res;

	msglen = strlen(message);
	if ((buf = malloc(keylen+msglen)) == NULL)
		goto fail;

	memcpy(buf, key, keylen);
	memcpy(buf+keylen, message, msglen);

	if ((res = sha1_hash(buf, keylen+msglen)) == NULL)
		goto fail;

	free(buf);
	return res;
fail:
	return NULL;
}

void
putx(uint8_t *buf, size_t len)
{
	while (len--)
		printf("%02x", *buf++);
	putchar('\n');
}

int
main(int argc, char **argv)
{
	uint8_t *res;

	if (argc != 3) {
		fprintf(stderr, "usage: %s key message\n", argv[0]);
		exit(1);
	}

	if ((res = sha1_mac(argv[1], strlen(argv[1]), argv[2])) == NULL)
		err(1, NULL);

	putx(res, SHA1_DIGEST_LENGTH);

	exit(0);
}
