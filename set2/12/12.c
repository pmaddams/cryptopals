#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

uint8_t *
encrypt(uint8_t *in, size_t inlen, size_t *outlenp)
{
	const char secret[] =
		"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
		"YnkK";

	static uint8_t key[16];
	BIO *b64_mem, *b64, *cip, *bio_out;
	FILE *memstream;
	char *out, buf[BUFSIZ];
	size_t outlen;
	ssize_t nr;

	while (*key == '\0')
		arc4random_buf(key, 16);

	if ((b64_mem = BIO_new_mem_buf((char *) secret, strlen(secret))) == NULL ||
	    (b64 = BIO_new(BIO_f_base64())) == NULL)
		goto fail;

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64, b64_mem);

	if ((memstream = open_memstream(&out, &outlen)) == NULL ||
	    (bio_out = BIO_new_fp(memstream, BIO_NOCLOSE)) == NULL ||
	    (cip = BIO_new(BIO_f_cipher())) == NULL)
		goto fail;

	BIO_set_cipher(cip, EVP_aes_128_ecb(), key, NULL, 1);
	BIO_push(cip, bio_out);

	if (BIO_write(cip, in, inlen) <= 0)
		goto fail;

	while ((nr = BIO_read(b64, buf, BUFSIZ)) > 0)
		if (BIO_write(cip, buf, nr) <= 0)
			goto fail;
	fclose(memstream);

	BIO_free_all(b64);
	BIO_free_all(cip);

	if (outlenp != NULL)
		*outlenp = outlen;

	return out;
fail:
	return NULL;
}

size_t
crack_blksiz(void)
{
	size_t res, inlen, outlen;
	uint8_t in[BUFSIZ], *out, save[3];

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
	uint8_t in[blksiz*2], *out;

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

int
main(void)
{
	size_t blksiz;

	if ((blksiz = crack_blksiz()) == 0)
		errx(1, "invalid block size");

	if (!is_ecb(blksiz))
		errx(1, "ECB required");

	exit(0);
}
