#include <sys/types.h>

#include <err.h>
#include <sha2.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#define DATA	"hi mom"

#define E	"3"
#define BITS	1024

char *
rsa_sign(RSA *rsa, char *buf, size_t len)
{
	X509_SIG sig;
	X509_ALGOR algor;
	ASN1_TYPE parameter;
	ASN1_OCTET_STRING digest;
	ssize_t rsa_size, siglen;

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
	    siglen + RSA_PKCS1_PADDING_SIZE > rsa_size)
		goto fail;

	warnx("signature length %d", siglen);
	warnx("padding length %d", RSA_PKCS1_PADDING_SIZE);
	warnx("rsa size %d", RSA_size(rsa));
fail:
	return NULL;
}

char *
rsa_forge(RSA *rsa, char *buf, size_t len)
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

	rsa_sign(rsa, DATA, strlen(DATA));

	return 0;
}
