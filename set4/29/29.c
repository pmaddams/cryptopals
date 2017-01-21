#include <sys/types.h>

#include <endian.h>
#include <err.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MESSAGE	"comment1=cooking%20MCs;userdata=foo;" \
		"comment2=%20like%20a%20pound%20of%20bacon"
#define APPEND	";admin=true"

#define BLKSIZ	64
#define PADSIZ	56
#define NSTATE	5

uint8_t *
sha1_mac(uint8_t *buf, size_t len)
{
	static uint8_t *key;
	static size_t keylen;
	uint8_t *res;
	SHA1_CTX ctx;

	if (key == NULL) {
		keylen = arc4random_uniform(BLKSIZ);
		if ((key = malloc(keylen)) == NULL)
			goto fail;
	}

	if ((res = malloc(SHA1_DIGEST_LENGTH)) == NULL)
		goto fail;

	SHA1Init(&ctx);
	SHA1Update(&ctx, (u_int8_t *) key, keylen);
	SHA1Update(&ctx, (u_int8_t *) buf, len);
	SHA1Final((u_int8_t *) res, &ctx);

	return res;
fail:
	return NULL;
}

uint8_t *
sha1_forge_mac(uint8_t *mac, size_t guess, char *message, char *append)
{
	uint8_t *res;
	SHA1_CTX ctx;
	size_t i, bytecount;

	if ((res = malloc(SHA1_DIGEST_LENGTH)) == NULL)
		goto done;

	if ((bytecount = guess+strlen(message)) % BLKSIZ >= PADSIZ)
		bytecount += BLKSIZ;
	ctx.count = ((bytecount/BLKSIZ + 1) * BLKSIZ) * 8;

	for (i = 0; i < NSTATE; i++)
		ctx.state[i] = htobe32(((uint32_t *) mac)[i]);

	SHA1Update(&ctx, (u_int8_t *) append, strlen(append));
	SHA1Final((u_int8_t *) res, &ctx);
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

uint8_t *
make_attack(size_t guess, char *message, char *append, size_t *lenp)
{
	FILE *memstream;
	char *buf;
	size_t len, msglen, npad;
	uint64_t bitcount;

	if ((memstream = open_memstream(&buf, &len)) == NULL)
		goto fail;

	msglen = strlen(message);
	npad = padlen(guess+msglen);

	if (fputs(message, memstream) == EOF ||
	    fputc('\x80', memstream) == EOF)
		goto fail;

	while (--npad)
		if (fputc('\x00', memstream) == EOF)
			goto fail;

	bitcount = htobe64((guess+msglen)*8);
	if (fwrite(&bitcount, sizeof(bitcount), 1, memstream) < 1 ||
	    fputs(append, memstream) == EOF)
		goto fail;
	fclose(memstream);

	if (lenp != NULL)
		*lenp = len;

	return buf;
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
main(void)
{
	uint8_t *mac, *forge, *buf, *check;
	size_t guess, len;

	if ((mac = sha1_mac(MESSAGE, strlen(MESSAGE))) == NULL)
		err(1, NULL);

	for (guess = 0; guess < BLKSIZ; guess++) {
		if ((forge = sha1_forge_mac(mac, guess, MESSAGE, APPEND)) == NULL ||
		    (buf = make_attack(guess, MESSAGE, APPEND, &len)) == NULL ||
		    (check = sha1_mac(buf, len)) == NULL)
			err(1, NULL);
		if (memcmp(forge, check, SHA1_DIGEST_LENGTH) == 0)
			break;
		free(forge);
		free(check);
	}
	if (guess == BLKSIZ)
		errx(1, "forgery failed");

	putx(forge, SHA1_DIGEST_LENGTH);
	putx(check, SHA1_DIGEST_LENGTH);

	exit(0);
}
