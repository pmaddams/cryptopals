#include <sys/types.h>

#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define BLKSIZ	16

#define MATCH	";admin=true;"
#define CLOAK	29

#define DECRYPT	0
#define ENCRYPT	1

uint8_t *
cbc_crypt(uint8_t *in, size_t inlen, size_t *outlenp, int enc)
{
	const char
	    *prefix = "comment1=cooking%20MCs;userdata=",
	    *suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
	static uint8_t key[BLKSIZ], iv[BLKSIZ];
	char *clean, c, *out;
	FILE *memstream;
	size_t i, j, outlen;
	BIO *cip, *bio_out;
	ssize_t nr;

	while (*key == '\0')
		arc4random_buf(key, BLKSIZ);

	if (enc == ENCRYPT) {
		if ((clean = malloc(inlen*3)) == NULL)
			goto fail;
		for (i = j = 0; i < inlen; i++)
			switch (c = in[i]) {
			case ';':
			case '=':
				clean[j++] = '"';
				clean[j++] = c;
				clean[j++] = '"';
				break;
			default:
				clean[j++] = c;
				break;
			}
		in = clean;
		inlen = j;
	}

	if ((memstream = open_memstream(&out, &outlen)) == NULL ||
	    (cip = BIO_new(BIO_f_cipher())) == NULL ||
	    (bio_out = BIO_new_fp(memstream, BIO_NOCLOSE)) == NULL)
		goto fail;

	BIO_set_cipher(cip, EVP_aes_128_cbc(), key, iv, enc);
	BIO_push(cip, bio_out);

	if ((BIO_write(cip, prefix, strlen(prefix))) <= 0 ||
	    (BIO_write(cip, in, inlen)) <= 0 ||
	    (BIO_write(cip, suffix, strlen(suffix))) <= 0)
		goto fail;

	BIO_flush(cip);
	fclose(memstream);
	BIO_free_all(cip);

	if (enc == ENCRYPT)
		free(clean);

	if (outlenp != NULL)
		*outlenp = outlen;

	return out;
fail:
	return NULL;
}

bool
is_admin(uint8_t *buf, size_t len)
{
	return memmem(buf, len, MATCH, strlen(MATCH)) ? true : false;
}

int
main(void)
{
	uint8_t *in, *enc, *out;
	size_t i, matchlen, inlen, enclen, outlen;

	matchlen = strlen(MATCH);
	inlen = BLKSIZ + matchlen;

	if ((in = malloc(inlen)) == NULL)
		err(1, NULL);

	memset(in, 'A', BLKSIZ);
	for (i = 0; i < matchlen; i++)
		in[BLKSIZ+i] = MATCH[i] ^ CLOAK;

	if ((enc = cbc_crypt(in, inlen, &enclen, ENCRYPT)) == NULL)
		err(1, NULL);

	for (i = 0; i < matchlen; i++)
		enc[BLKSIZ*2+i] ^= CLOAK;

	if ((out = cbc_crypt(enc, enclen, &outlen, DECRYPT)) == NULL)
		err(1, NULL);

	printf("admin=%s\n", is_admin(out, outlen) ? "true" : "false");

	exit(0);
}
