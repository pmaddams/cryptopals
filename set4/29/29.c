#include <sys/types.h>

#include <endian.h>
#include <err.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NSTATES	5
#define BLKSIZ	64
#define PADSIZ	56

uint8_t *
sha1_mac(uint8_t *buf, size_t len)
{
	static uint8_t *key;
	static size_t keylen;
	uint8_t *res;
	SHA1_CTX ctx;

	if (key == NULL) {
		keylen = arc4random_uniform(BLKSIZ)+1;
		if ((key = malloc(keylen)) == NULL)
			goto fail;
		arc4random_buf(key, keylen);
	}

	if ((res = malloc(SHA1_DIGEST_LENGTH)) == NULL)
		goto fail;

	SHA1Init(&ctx);
	SHA1Update(&ctx, key, keylen);
	SHA1Update(&ctx, buf, len);
	SHA1Final(res, &ctx);

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

	for (i = 0; i < NSTATES; i++)
		ctx.state[i] = htobe32(((uint32_t *) mac)[i]);

	SHA1Update(&ctx, append, strlen(append));
	SHA1Final(res, &ctx);
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
	char *message, *append;
	uint8_t *mac, *forge, *buf, *check;
	size_t guess, len;

	message = "comment1=cooking%20MCs;userdata=foo;"
		  "comment2=%20like%20a%20pound%20of%20bacon";
	append = ";admin=true";

	if ((mac = sha1_mac(message, strlen(message))) == NULL)
		err(1, NULL);

	for (guess = 1; guess <= BLKSIZ; guess++) {
		if ((forge = sha1_forge_mac(mac, guess, message, append)) == NULL ||
		    (buf = make_attack(guess, message, append, &len)) == NULL ||
		    (check = sha1_mac(buf, len)) == NULL)
			err(1, NULL);
		if (memcmp(forge, check, SHA1_DIGEST_LENGTH) == 0)
			break;
		free(forge);
		free(check);
	}
	if (guess > BLKSIZ)
		errx(1, "forgery failed");

	putx(forge, SHA1_DIGEST_LENGTH);
	putx(check, SHA1_DIGEST_LENGTH);

	exit(0);
}
