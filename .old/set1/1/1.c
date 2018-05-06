#include <ctype.h>
#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define FILENAME "DATA"

int
getx(FILE *fp)
{
	int i, c;
	static char buf[3];

	for (i = 0; i < 2;)
		if (isxdigit(c = getc(fp)))
			buf[i++] = c;
		else if (c == EOF)
			return EOF;

	return strtol(buf, NULL, 16);
}

int
main(void)
{
	FILE *fp;
	BIO *bio, *b64;
	int c;

	if ((fp = fopen(FILENAME, "r")) == NULL ||
	    (b64 = BIO_new(BIO_f_base64())) == NULL ||
	    (bio = BIO_new_fp(stdout, BIO_NOCLOSE)) == NULL)
		err(1, NULL);

	BIO_push(b64, bio);

	while ((c = getx(fp)) != EOF)
		if (BIO_write(b64, &c, 1) < 1)
			err(1, NULL);

	BIO_flush(b64);

	exit(0);
}
