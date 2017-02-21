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

void
putx(uint8_t *buf, size_t len)
{
	while (len--)
		printf("%02x", *buf++);
	putchar('\n');
}

uint8_t *
asn1_sign(uint8_t *inbuf, size_t inlen, size_t *outlenp)
{
	X509_SIG sig;
	X509_ALGOR algor;
	ASN1_TYPE parameter;
	ASN1_OCTET_STRING digest;
	ssize_t outlen;
	uint8_t *res, *p;

	sig.algor = &algor;
	if ((sig.algor->algorithm = OBJ_nid2obj(NID_sha256)) == NULL)
		goto fail;

	parameter.type = V_ASN1_NULL;
	parameter.value.ptr = NULL;
	sig.algor->parameter = &parameter;

	sig.digest = &digest;
	sig.digest->data = inbuf;
	sig.digest->length = inlen;

	if ((outlen = i2d_X509_SIG(&sig, NULL)) <= 0 ||
	    (res = malloc(outlen)) == NULL)
		goto fail;

	p = res;
	if (i2d_X509_SIG(&sig, &p) < outlen)
		goto fail;

	if (outlenp != NULL)
		*outlenp = outlen;

	return res;
fail:
	return NULL;
}

char *
rsa_sign(RSA *rsa, uint8_t *buf, size_t len)
{
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

	asn1_sign(DATA, strlen(DATA), NULL);

	exit(0);
}
