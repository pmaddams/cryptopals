#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#define BITS 1024

const char *data = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";

BIGNUM *
rsa_encrypt_b64(RSA *rsa, char *buf)
{
	size_t len;
	char *tmp;

	len = strlen(buf);
	if ((tmp = malloc(len)) == NULL ||

	    EVP_DecodeBlock(tmp, buf, strlen(buf)) == 0)
		goto fail;

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

	if ((rsa = RSA_new()) == NULL ||
	    (f4 = BN_new()) == NULL ||

	    BN_set_word(f4, RSA_F4) == 0 ||
	    RSA_generate_key_ex(rsa, BITS, f4, NULL) == 0)
		err(1, NULL);

	rsa_encrypt_b64(rsa, (char *) data);
}
