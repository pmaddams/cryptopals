#include <sys/types.h>

#include <err.h>
#include <sha2.h>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#define DATA	"hi mom"

#define E	"3"
#define BITS	1024

char *
rsa_sign(RSA *rsa, char *buf)
{
}

char *
rsa_forge(RSA *rsa, char *buf)
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
}
