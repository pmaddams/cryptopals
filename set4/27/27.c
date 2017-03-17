#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#define BLKSIZ	16

#define ENCRYPT	1
#define DECRYPT	0

void
putx(uint8_t *buf, size_t len)
{
	while (len--)
		printf("%02x", *buf++);
	putchar('\n');
}

uint8_t *
cbc_crypt(uint8_t *in, size_t inlen, size_t *outlenp, int enc)
{
	const char
	    *prefix = "comment1=cooking%20MCs;userdata=",
	    *suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
	size_t i, outlen;
	static uint8_t key[BLKSIZ];
	BIO *cip, *bio_out;
	FILE *memstream;
	char *out;

	while (*key == '\0') {
		arc4random_buf(key, BLKSIZ);
		putx(key, BLKSIZ);
	}

	if ((cip = BIO_new(BIO_f_cipher())) == NULL ||
	    (memstream = open_memstream(&out, &outlen)) == NULL ||
	    (bio_out = BIO_new_fp(memstream, BIO_NOCLOSE)) == NULL)
		goto fail;

	BIO_set_cipher(cip, EVP_aes_128_cbc(), key, key, enc);
	BIO_push(cip, bio_out);

	if (enc && BIO_write(cip, prefix, strlen(prefix)) <= 0 ||
	    BIO_write(cip, in, inlen) <= 0 ||
	    enc && BIO_write(cip, suffix, strlen(suffix)) <= 0)
			goto fail;

	BIO_flush(cip);
	fclose(memstream);

	BIO_free_all(cip);

	if (outlenp != NULL)
		*outlenp = outlen;

	return out;
fail:
	return NULL;
}

int
main(void)
{
	size_t i, inlen, enclen;
	uint8_t *in, *enc, *out;

	inlen = BLKSIZ*3;
	if ((in = malloc(inlen)) == NULL)
		err(1, NULL);
	memset(in, 'A', inlen);

	if ((enc = cbc_crypt(in, inlen, &enclen, ENCRYPT)) == NULL)
		err(1, NULL);

	memset(enc+BLKSIZ, 0, BLKSIZ);
	memcpy(enc+BLKSIZ*2, enc, BLKSIZ);

	if ((out = cbc_crypt(enc, enclen, NULL, DECRYPT)) == NULL)
		err(1, NULL);

	for (i = 0; i < BLKSIZ; i++)
		out[i] ^= out[i+BLKSIZ*2];

	putx(out, BLKSIZ);

	exit(0);
}
