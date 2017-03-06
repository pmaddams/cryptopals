#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#define BITS 1024

const char *data = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";

char *
rsa_encrypt_b64(RSA *rsa, char *buf)
{
	ssize_t buflen, tmplen;
	char *tmp, *res;

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
check_parity()
{
}

int
main(void)
{
	RSA *rsa;
	BIGNUM *f4;
	char *enc;

	if ((rsa = RSA_new()) == NULL ||
	    (f4 = BN_new()) == NULL ||

	    BN_set_word(f4, RSA_F4) == 0 ||
	    RSA_generate_key_ex(rsa, BITS, f4, NULL) == 0 ||

	    (enc = rsa_encrypt_b64(rsa, (char *) data)) == NULL)
		err(1, NULL);
}
