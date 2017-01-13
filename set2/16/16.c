#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define BLKSIZ 16

uint8_t *
encrypt(uint8_t *in, size_t inlen, size_t *outlenp)
{
	const uint8_t
	    *prefix = "comment1=cooking%20MCs;userdata=",
	    *suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
	static size_t pfxlen, sfxlen;
	static uint8_t key[BLKSIZ], iv[BLKSIZ];
	static BIO *cip;
	uint8_t *clean;
	FILE *memstream;
	char *out, c, buf[BUFSIZ];
	size_t i, j, outlen;
	ssize_t nr;

	if (pfxlen == 0)
		pfxlen = strlen(prefix);
	if (sfxlen == 0)
		sfxlen = strlen(suffix);

	while (*key == '\0')
		arc4random_buf(key, BLKSIZ);

	if (cip == NULL) {
		if ((cip = BIO_new(BIO_f_cipher())) == NULL)
			goto fail;
		BIO_set_cipher(cip, EVP_aes_128_cbc(), key, iv, 1);
	} else
		BIO_reset(cip);

	if ((clean = malloc(inlen*3)) == NULL ||
	    (memstream = open_memstream(&out, &outlen)) == NULL)
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

	inlen = j;

	if ((BIO_write(cip, prefix, pfxlen)) < pfxlen ||
	    (BIO_write(cip, clean, inlen)) < inlen ||
	    (BIO_write(cip, suffix, sfxlen)) < sfxlen)
		goto fail;
	BIO_flush(cip);

	free(clean);

	while ((nr = BIO_read(cip, buf, BUFSIZ)) > 0)
		if (fwrite(buf, nr, 1, memstream) < 1)
			goto fail;
	fclose(memstream);

	if (outlenp != NULL)
		*outlenp = outlen;

	return out;
fail:
	return NULL;
}

int
main(void)
{
	uint8_t *enc;

	if ((enc = encrypt("", 0, NULL)) == NULL)
		err(1, NULL);

	exit(0);
}
