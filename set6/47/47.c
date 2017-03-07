#include <openssl/bn.h>
#include <openssl/rsa.h>

#define BITS 256

const char *data = "kick it, CC";

char *
rsa_encrypt(RSA *rsa, char *buf)
{

}

int
check_padding(RSA *rsa, char *enc)
{

}

int
main(void)
{
	return 0;
}
