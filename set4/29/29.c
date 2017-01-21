#include <sys/types.h>

#include <err.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLKSIZ 64
#define PADSIZ 56

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

size_t
padlen(size_t len)
{
	if ((len %= BLKSIZ) >= PADSIZ)
		return PADSIZ + BLKSIZ - len;
	else
		return PADSIZ - len;
}
