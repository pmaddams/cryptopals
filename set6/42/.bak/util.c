#include <stdlib.h>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include "42.h"

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

int
cubert(BIGNUM *res, BIGNUM *bn, BN_CTX *ctx)
{
	BIGNUM *out, *two, *three, *t1, *t2;

	if ((out = BN_CTX_get(ctx)) == NULL ||
	    (two = BN_CTX_get(ctx)) == NULL ||
	    (three = BN_CTX_get(ctx)) == NULL ||
	    (t1 = BN_CTX_get(ctx)) == NULL ||
	    (t2 = BN_CTX_get(ctx)) == NULL ||

	    BN_copy(out, bn) == NULL ||
	    BN_dec2bn(&two, "2") == 0 ||
	    BN_dec2bn(&three, "3") == 0)
		goto fail;

	for (;;) {
		if (BN_exp(t1, out, two, ctx) == 0 ||
		    BN_div(t1, NULL, bn, t1, ctx) == 0 ||

		    BN_mul(t2, out, two, ctx) == 0 ||

		    BN_add(t1, t1, t2) == 0 ||
		    BN_div(t1, NULL, t1, three, ctx) == 0)
			goto fail;

		if (BN_cmp(out, t1) == 0)
			break;
		if (BN_copy(out, t1) == NULL)
			goto fail;
	}

	return BN_copy(res, out) != NULL;
fail:
	return 0;
}
