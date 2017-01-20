#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#define BLKSIZ	16

#define ENCRYPT	1
#define DECRYPT	0

uint8_t *
cbc_crypt(uint8_t *in, size_t inlen, size_t *outlenp, int enc)
{
	const char
	    *prefix = "comment1=cooking%20MCs;userdata=",
	    *suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
	static uint8_t key[BLKSIZ];
	BIO *cip, *bio_out;
	FILE *memstream;
	char *out;
	size_t outlen;

	while (*key == '\0')
		arc4random_buf(key, BLKSIZ);

	if ((cip = BIO_new(BIO_f_cipher())) == NULL ||
	    (memstream = open_memstream(&out, &outlen)) == NULL ||
	    (bio_out = BIO_new_fp(memstream, BIO_NOCLOSE)) == NULL)
		goto fail;

	BIO_set_cipher(cip, EVP_aes_128_cbc(), key, key, enc);
	BIO_push(cip, bio_out);

	if (BIO_write(cip, prefix, strlen(prefix)) <= 0 ||
	    BIO_write(cip, in, inlen) <= 0 ||
	    BIO_write(cip, suffix, strlen(suffix)) <= 0)
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
	exit(0);
}
