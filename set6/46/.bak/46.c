#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#define BITS	1024

const char *data = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";

uint8_t *
rsa_encrypt_b64(RSA *rsa, char *buf)
{
	ssize_t buflen, tmplen;
	uint8_t *tmp, *res;

	buflen = strlen(buf);
	if ((tmp = malloc(buflen)) == NULL ||
	    (res = malloc(RSA_size(rsa))) == NULL ||

	    (tmplen = EVP_DecodeBlock(tmp, buf, buflen)) == 0 ||
	    RSA_public_encrypt(tmplen, tmp, res, rsa, RSA_PKCS1_PADDING) == -1)
		goto fail;

	free(tmp);
	return res;
fail:
	return NULL;
}

int
is_plaintext_even(RSA *rsa, uint8_t *enc)
{
	ssize_t rsa_size, declen;
	char *dec;
	int res;

	rsa_size = RSA_size(rsa);
	if ((dec = malloc(rsa_size)) == NULL ||

	    (declen = RSA_private_decrypt(rsa_size, enc, dec, rsa, RSA_PKCS1_PADDING)) == -1)
		goto fail;

	res = !(dec[declen-1] & 1);

	free(dec);
	return res;
fail:
	return -1;
}

BIGNUM *
crack_rsa(RSA *rsa, uint8_t *enc)
{
	BN_CTX *ctx;
	BIGNUM *lower, *upper;

	
}

int
main(void)
{
	RSA *rsa;
	BIGNUM *f4;
	uint8_t *enc;
	int even;

	if ((rsa = RSA_new()) == NULL ||
	    (f4 = BN_new()) == NULL ||

	    BN_set_word(f4, RSA_F4) == 0 ||
	    RSA_generate_key_ex(rsa, BITS, f4, NULL) == 0 ||

	    (enc = rsa_encrypt_b64(rsa, (char *) data)) == NULL)
		err(1, NULL);

	exit(0);
}
