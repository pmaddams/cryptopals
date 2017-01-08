#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define SECRET							\
"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"	\
"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"	\
"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"	\
"YnkK"

#define HASHSIZE 1000

struct entry {
	uint8_t *blk;
	char c;
	struct entry *next;
};

struct entry *tab[HASHSIZE];

uint8_t *
encrypt(uint8_t *in, size_t inlen, size_t *outlenp)
{
	static char key[16];
	EVP_CIPHER_CTX ctx;
	char *outbuf;
	int outlen, tmplen;

	while (*key == '\0')
		arc4random_buf(key, 16);

	EVP_CIPHER_CTX_init(&ctx);

	if ((outbuf = malloc(inlen+16)) == NULL ||
	    EVP_EncryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key, NULL) == 0 ||
	    EVP_EncryptUpdate(&ctx, outbuf, &outlen, in, inlen) == 0 ||
	    EVP_EncryptFinal_ex(&ctx, outbuf+outlen, &tmplen) == 0)
		goto fail;

	EVP_CIPHER_CTX_cleanup(&ctx);

	outlen += tmplen;
	if (outlenp != NULL)
		*outlenp = outlen;

	return outbuf;
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

bool
is_ecb(size_t blksiz)
{
	bool res;
	char in[blksiz*2], *out;

	res = false;

	memset(in, 'A', blksiz*2);
	if ((out = encrypt(in, blksiz*2, NULL)) == NULL)
		goto done;

	if (memcmp(out, out+blksiz, blksiz) == 0)
		res = true;

	free(out);
done:
	return res;
}

unsigned int
hash(uint8_t *blk, size_t blksiz)
{
	unsigned int h;

	for (h = 0; blksiz--;)
		h = h * 31 + *blk++;

	return h % HASHSIZE;
}

char
lookup(uint8_t *blk, size_t blksiz, char c, int create)
{
	unsigned int h;
	struct entry *p;

	h = hash(blk, blksiz);

	for (p = tab[h]; p != NULL; p = p->next)
		if (memcmp(blk, p->blk, blksiz) == 0)
			goto done;

	if (create) {
		if ((p = malloc(sizeof(*p))) == NULL ||
		    (p->blk = malloc(blksiz)) == NULL)
			goto fail;

		memcpy(p->blk, blk, blksiz);
		p->c = c;
		p->next = tab[h];
		tab[h] = p;
	} else
		goto fail;
done:
	return p->c;
fail:
	return -1;
}

int
fill_tab(size_t blksiz)
{
	uint8_t in[blksiz], *out;
	char c;

	memset(in, 'A', blksiz-1);

	for (c = 0; c < CHAR_MAX; c++) {
		in[blksiz-1] = c;
		if ((out = encrypt(in, blksiz, NULL)) == NULL ||
		    lookup(out, blksiz, c, 1) == -1)
			goto fail;

		free(out);
	}

	return 1;
fail:
	return 0;
}

char *
crack_secret(size_t blksiz)
{
	FILE *memstream;
	char *in, tmp[BUFSIZ], *out, *enc, c;
	size_t i, inlen, outlen;
	BIO *b64_mem, *b64;
	ssize_t nr;

	if ((memstream = open_memstream(&in, &inlen)) == NULL)
		goto fail;

	for (i = 0; i < blksiz-1; i++)
		putc('A', memstream);

	if ((b64_mem = BIO_new_mem_buf(SECRET, strlen(SECRET))) == NULL ||
	    (b64 = BIO_new(BIO_f_base64())) == NULL)
		goto fail;

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64, b64_mem);

	while ((nr = BIO_read(b64, tmp, BUFSIZ)) > 0)
		if (fwrite(tmp, nr, 1, memstream) < 1)
			goto fail;
	fclose(memstream);

	BIO_free_all(b64);

	if ((memstream = open_memstream(&out, &outlen)) == NULL)
		goto fail;

	while (inlen >= blksiz) {
		if ((enc = encrypt(in, blksiz, NULL)) == NULL ||
		    (c = lookup(enc, blksiz, 0, 0)) == -1)
			goto fail;

		putc(c, memstream);
		memmove(in+blksiz-1, in+blksiz, inlen-blksiz);

		free(enc);
		inlen--;
	}
	fclose(memstream);

	return out;
fail:
	return NULL;
}

int
main(void)
{
	size_t blksiz;
	char *s;

	if ((blksiz = crack_blksiz()) == 0)
		errx(1, "invalid block size");

	if (!is_ecb(blksiz))
		errx(1, "ECB required");

	if (fill_tab(blksiz) == 0 ||
	    (s = crack_secret(blksiz)) == NULL)
		err(1, NULL);

	puts(s);

	exit(0);
}
