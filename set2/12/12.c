#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define HASHSIZ 127

struct entry {
	uint8_t *blk;
	char c;
	struct entry *next;
};

const char secret[] =
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK";

struct entry *tab[HASHSIZ];

uint8_t *
encrypt(uint8_t *in, size_t inlen, size_t *outlenp)
{
	static char key[16];
	FILE *out;
	char *buf;
	size_t len;
	BIO *cip, *bio_out;

	while (*key == '\0')
		arc4random_buf(key, 16);

	if ((out = open_memstream(&buf, &len)) == NULL ||
	    (cip = BIO_new(BIO_f_cipher())) == NULL ||
	    (bio_out = BIO_new_fp(out, BIO_NOCLOSE)) == NULL)
		goto fail;

	BIO_set_cipher(cip, EVP_aes_128_ecb(), key, NULL, 1);
	BIO_push(cip, bio_out);

	if (BIO_write(cip, in, inlen) < inlen)
		goto fail;

	BIO_flush(cip);
	BIO_free_all(cip);
	fclose(out);

	if (outlenp != NULL)
		*outlenp = len;

	return buf;
fail:
	return NULL;
}

size_t
crack_blksiz(void)
{
	size_t res, inlen, outlen;
	char in[BUFSIZ], *out, save[3];

	for (res = 0, inlen = 1; inlen < BUFSIZ; inlen++) {
		in[inlen-1] = 'A';
		if ((out = encrypt(in, inlen, &outlen)) == NULL || outlen < 3)
			goto done;
		if (memcmp(save, out, 3) == 0) {
			res = inlen-1;
			break;
		}
		memcpy(save, out, 3);
		free(out);
	}
done:
	return res;
}

int
is_ecb(size_t blksiz)
{
	char in[blksiz*2], *out;

	memset(in, 'A', blksiz*2);

	if ((out = encrypt(in, blksiz*2, NULL)) == NULL)
		goto fail;

	free(out);

	return (memcmp(out, out+blksiz, blksiz) == 0);
fail:
	return 0;
}

uint8_t
hash(uint8_t *blk, size_t blksiz)
{
	uint64_t h;

	for (h = 0; blksiz--;)
		h = h * 31 + *blk++;

	return h % HASHSIZ;
}

char
lookup(uint8_t *blk, size_t blksiz, char c, int creat)
{
	uint8_t h;
	struct entry *p;

	h = hash(blk, blksiz);

	for (p = tab[h]; p != NULL; p = p->next)
		if (memcmp(blk, p->blk, blksiz) == 0)
			goto done;

	if (creat) {
		if ((p = malloc(sizeof(*p))) == NULL ||
		    (p->blk = malloc(blksiz)) == NULL)
			goto fail;

		memcpy(p->blk, blk, blksiz);
		p->c = c;
		p->next = tab[h];
		tab[h] = p;
	}
done:
	return p->c;
fail:
	return -1;
}

int
main(void)
{
	puts(is_ecb(crack_blksiz()) ? "yes" : "no");
	return 0;
}
