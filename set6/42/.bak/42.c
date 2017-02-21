#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#define DATA	"hi mom"

#define E	"3"
#define BITS	1024

uint8_t *
rsa_asn1(RSA *rsa, uint8_t *buf, size_t len)
{
	X509_SIG sig;
	X509_ALGOR algor;
	ASN1_TYPE parameter;
	ASN1_OCTET_STRING digest;
	ssize_t rsa_size, siglen;
	uint8_t *res, *p;

	sig.algor = &algor;
	if ((sig.algor->algorithm = OBJ_nid2obj(NID_sha256)) == NULL)
		goto fail;

	parameter.type = V_ASN1_NULL;
	parameter.value.ptr = NULL;
	sig.algor->parameter = &parameter;

	sig.digest = &digest;
	sig.digest->data = buf;
	sig.digest->length = len;

	rsa_size = RSA_size(rsa);
	if ((siglen = i2d_X509_SIG(&sig, NULL)) <= 0 ||
	    siglen + RSA_PKCS1_PADDING_SIZE > rsa_size ||

	    (res = malloc(rsa_size)) == NULL)
		goto fail;

	p = res;
	if (i2d_X509_SIG(&sig, &p) < siglen)
		goto fail;

	return res;
fail:
	return NULL;
}

char *
rsa_forge(RSA *rsa, uint8_t *buf, size_t len)
{
}

int
rsa_verify(RSA *rsa, char *sig)
{
}

int
main(void)
{
	RSA *rsa;
	BIGNUM *e;

	if ((rsa = RSA_new()) == NULL ||
	    (e = BN_new()) == NULL ||

	    BN_dec2bn(&e, E) == 0 ||

	    RSA_generate_key_ex(rsa, BITS, e, NULL) == 0)
		err(1, NULL);

	exit(0);
}
