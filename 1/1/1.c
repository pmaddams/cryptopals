#include <ctype.h>
#include <err.h>
#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

int
gethex(FILE *fp)
{
	int i, c;
	static char buf[3];

	for (i = 0; i < 2;)
		if (isxdigit(c = getchar()))
			buf[i++] = c;
		else if (c == EOF)
			goto fail;

	return strtol(buf, NULL, 16);
fail:
	return EOF;
}

int
main(void)
{
	BIO *bio, *b64;
	int c;

	if ((b64 = BIO_new(BIO_f_base64())) == NULL ||
	    (bio = BIO_new_fp(stdout, BIO_NOCLOSE)) == NULL)
		err(1, NULL);

	BIO_push(b64, bio);

	while ((c = gethex(stdin)) != EOF)
		if (BIO_write(b64, &c, 1) <= 0)
			err(1, NULL);

	BIO_flush(b64);
	BIO_free_all(b64);

	return 0;
}
