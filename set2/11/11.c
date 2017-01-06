#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define KEY	"YELLOW SUBMARINE"
#define BLKSIZ	16

char *
extend(char *buf, size_t *lenp)
{
	size_t prefix, suffix, newlen;
	char *newbuf;

	prefix = arc4random_uniform(6)+5;
	suffix = arc4random_uniform(6)+5;

	newlen = prefix + *lenp + suffix;
	if ((newbuf = malloc(newlen+1)) == NULL)
		goto done;

	arc4random_buf(newbuf, prefix);
	memcpy(newbuf+prefix, buf, *lenp);
	arc4random_buf(newbuf+prefix+*lenp, suffix);

	newbuf[newlen] = '\0';
	*lenp = newlen;
done:
	return newbuf;
}

int
encrypt(FILE *in, FILE *out, uint8_t *key, int *modep)
{
	BIO *bio, *cip;
	const EVP_CIPHER *cipher;
	char buf[BUFSIZ];
	int nr;

	if ((bio = BIO_new_fp(in, BIO_NOCLOSE)) == NULL ||
	    (cip = BIO_new(BIO_f_cipher())) == NULL)
		goto fail;

	cipher = (*modep = arc4random_uniform(2)) ?
	    EVP_aes_128_ecb() : EVP_aes_128_cbc();

	BIO_set_cipher(cip, cipher, key, NULL, 1);
	BIO_push(cip, bio);

	while ((nr = BIO_read(cip, buf, BUFSIZ)) > 0)
		if (fwrite(buf, nr, 1, out) < 1)
			goto fail;

	return 1;
fail:
	return 0;
}

int
main(void)
{
	char *buf;
	size_t len;

	len = BLKSIZ*3;
	if ((buf = malloc(len+1)) == NULL)
		err(1, NULL);
	memset(buf, 'A', len);

	if ((buf = extend(buf, &len)) == NULL)
		err(1, NULL);

	puts(buf);

	exit(0);
}
