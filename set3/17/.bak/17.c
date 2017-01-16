#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#define BLKSIZ 16

uint8_t *
cbc_crypt(uint8_t *in, size_t inlen, size_t *outlenp, int enc)
{
	static uint8_t key[BLKSIZ], iv[BLKSIZ];
	uint8_t *out;
	int outlen, tmplen;
	EVP_CIPHER_CTX ctx;

	if (*key == '\0')
		arc4random_buf(key, BLKSIZ);

	if ((out = malloc(inlen+BLKSIZ)) == NULL)
		goto fail;

	EVP_CIPHER_CTX_init(&ctx);
	EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv, enc);

	if ((EVP_CipherUpdate(&ctx, out, &outlen, in, inlen)) == 0 ||
	    (EVP_CipherFinal(&ctx, out+outlen, &tmplen)) == 0)
		goto fail;

	outlen += tmplen;
	if (outlenp != NULL)
		*outlenp = outlen;

	return out;
fail:
	free(out);
	return NULL;
}

uint8_t *
make_secret(size_t *lenp)
{
	const char *s, *choices[10] = {
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
	};
	char *in, tmp[BUFSIZ], *out;
	BIO *b64_mem, *b64;
	FILE *memstream;
	size_t inlen, outlen;
	ssize_t nr;

	s = choices[arc4random_uniform(10)];

	if ((b64_mem = BIO_new_mem_buf((char *) s, strlen(s))) == NULL ||
	    (b64 = BIO_new(BIO_f_base64())) == NULL ||
	    (memstream = open_memstream(&in, &inlen)) == NULL)
		goto fail;

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64, b64_mem);

	while ((nr = BIO_read(b64, tmp, BUFSIZ)) > 0)
		if (fwrite(tmp, nr, 1, memstream) < 1)
			goto fail;
	fclose(memstream);

	BIO_free_all(b64);

	if ((out = cbc_crypt(in, inlen, &outlen, 1)) == NULL)
		goto fail;

	if (lenp != NULL)
		*lenp = outlen;

	free(in);
	return out;
fail:
	return NULL;
}

int
main(void)
{
	char *s;

	if ((s = make_secret(NULL)) == NULL)
		err(1, NULL);

	puts(s);

	exit(0);
}
