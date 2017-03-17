#include <sys/types.h>

#include <err.h>
#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define FILENAME	"DATA"

#define KEY		"YELLOW SUBMARINE"

int
main(void)
{
	FILE *fp;
	BIO *bio, *b64, *cip;
	char buf[BUFSIZ];
	ssize_t nr;

	if ((fp = fopen(FILENAME, "r")) == NULL ||
	    (bio = BIO_new_fp(fp, BIO_NOCLOSE)) == NULL ||
	    (b64 = BIO_new(BIO_f_base64())) == NULL ||
	    (cip = BIO_new(BIO_f_cipher())) == NULL)
		err(1, NULL);

	BIO_set_cipher(cip, EVP_aes_128_ecb(), KEY, NULL, 0);
	BIO_push(cip, b64);
	BIO_push(b64, bio);

	while ((nr = BIO_read(cip, buf, BUFSIZ)) > 0)
		fwrite(buf, nr, 1, stdout);

	return 0;
}
