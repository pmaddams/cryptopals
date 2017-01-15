#include <err.h>
#include <limits.h>
#include <stdlib.h>

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

int
main(void)
{
	return 0;
}
