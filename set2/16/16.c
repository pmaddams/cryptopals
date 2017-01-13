#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define BLKSIZ 16

uint8_t *
encrypt(uint8_t *in, size_t inlen, size_t *outlenp)
{
	const char
	    *prefix = "comment1=cooking%20MCs;userdata=",
	    *suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
	static uint8_t key[BLKSIZ], iv[BLKSIZ];
	char *clean, *out, c, buf[BUFSIZ];
	FILE *memstream;
	size_t i, j, outlen, pfxlen, sfxlen;
	BIO *cip, *bio_out;
	ssize_t nr;

	while (*key == '\0')
		arc4random_buf(key, BLKSIZ);

	if ((clean = malloc(inlen*3)) == NULL ||
	    (memstream = open_memstream(&out, &outlen)) == NULL ||
	    (cip = BIO_new(BIO_f_cipher())) == NULL ||
	    (bio_out = BIO_new_fp(memstream, BIO_NOCLOSE)) == NULL)
		goto fail;

	BIO_set_cipher(cip, EVP_aes_128_cbc(), key, iv, 1);
	BIO_push(cip, bio_out);

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

	inlen = j;
	pfxlen = strlen(prefix);
	sfxlen = strlen(suffix);

	if ((BIO_write(cip, prefix, pfxlen)) < pfxlen ||
	    (BIO_write(cip, clean, inlen)) < inlen ||
	    (BIO_write(cip, suffix, sfxlen)) < sfxlen)
		goto fail;

	BIO_flush(cip);
	fclose(memstream);
	BIO_free_all(cip);
	free(clean);

	if (outlenp != NULL)
		*outlenp = outlen;

	return out;
fail:
	return NULL;
}

int
main(void)
{
}
