#include <sys/types.h>

#include <endian.h>
#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#define MATCH	";admin=true;"
#define CLOAK	29

#define BLKSIZ	16

#define DECRYPT	0
#define ENCRYPT	1

int
ctr_crypt_blk(EVP_CIPHER_CTX *ctxp, uint8_t *blk, uint64_t nonce, uint64_t ctr, uint8_t *key)
{
	uint8_t tmp[BLKSIZ], out[BLKSIZ];
	int i, len;

	nonce = htole64(nonce);
	ctr = htole64(ctr);

	memcpy(tmp, &nonce, BLKSIZ/2);
	memcpy(tmp+BLKSIZ/2, &ctr, BLKSIZ/2);

	if (EVP_EncryptInit_ex(ctxp, EVP_aes_128_ecb(), NULL, key, NULL) == 0 ||
	    EVP_EncryptUpdate(ctxp, out, &len, tmp, BLKSIZ) == 0)
		goto fail;

	for (i = 0; i < BLKSIZ; i++)
		blk[i] ^= out[i];

	return 1;
fail:
	return 0;
}

uint8_t *
ctr_crypt(uint8_t *in, size_t inlen, size_t *outlenp, uint64_t nonce, int enc)
{
	const char
	    *prefix = "comment1=cooking%20MCs;userdata=",
	    *suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
	static uint8_t key[BLKSIZ];
	EVP_CIPHER_CTX ctx;
	FILE *memstream;
	size_t i, outlen;
	char c, *out;
	uint64_t ctr;

	while (*key == '\0')
		arc4random_buf(key, BLKSIZ);

	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);

	if ((memstream = open_memstream(&out, &outlen)) == NULL)
		goto fail;

	if (enc == ENCRYPT) {
	    	if (fwrite(prefix, strlen(prefix), 1, memstream) < 1)
			goto fail;

		for (i = 0; i < inlen; i++)
			switch (c = in[i]) {
			case ';':
			case '=':
				if (putc('"', memstream) == EOF ||
				    putc(c, memstream) == EOF ||
				    putc('"', memstream) == EOF)
					goto fail;
				break;
			default:
				if (putc(c, memstream) == EOF)
					goto fail;
				break;
			}

		if (fwrite(suffix, strlen(suffix), 1, memstream) < 1)
			goto fail;
	} else
		if (fwrite(in, inlen, 1, memstream) < 1)
			goto fail;

	for (i = 0; i < BLKSIZ; i++)
		if (putc('\0', memstream) == EOF)
			goto fail;
	fclose(memstream);
	outlen -= BLKSIZ;

	for (ctr = i = 0; i < outlen; i += BLKSIZ, ctr++)
		if (ctr_crypt_blk(&ctx, out+i, nonce, ctr, key) == 0)
			goto fail;

	EVP_CIPHER_CTX_cleanup(&ctx);

	if (outlenp != NULL)
		*outlenp = outlen;

	out[outlen] = '\0';
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
	size_t i, inlen, enclen, outlen;
	uint8_t *in, *enc, *out;

	inlen = strlen(MATCH);
	if ((in = malloc(inlen)) == NULL)
		err(1, NULL);
	memcpy(in, MATCH, inlen);

	for (i = 0; i < inlen; i++)
		in[i] ^= CLOAK;

	if ((enc = ctr_crypt(in, inlen, &enclen, 0, ENCRYPT)) == NULL)
		err(1, NULL);

	for (i = 0; i < inlen; i++)
		enc[BLKSIZ*2+i] ^= CLOAK;

	if ((out = ctr_crypt(enc, enclen, &outlen, 0, DECRYPT)) == NULL)
		err(1, NULL);

	printf("admin=%s\n", is_admin(out, outlen) ? "true" : "false");

	exit(0);
}
