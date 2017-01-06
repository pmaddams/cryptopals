#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define BLKSIZ	16

#define ECB	0
#define CBC	1

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

	cipher = (*modep = arc4random_uniform(2)) == ECB ?
	    EVP_aes_128_ecb() : EVP_aes_128_cbc();

	BIO_set_cipher(cip, cipher, key, NULL, 1);
	BIO_push(cip, bio);

	while ((nr = BIO_read(cip, buf, BUFSIZ)) > 0)
		if (fwrite(buf, nr, 1, out) < 1)
			goto fail;

	BIO_free_all(bio);

	return 1;
fail:
	return 0;
}

int
main(void)
{
	char key[BLKSIZ], *buf, *outbuf;
	size_t len, outlen;
	FILE *in, *out;
	int realmode, guessmode;

	arc4random_buf(key, BLKSIZ);

	len = BLKSIZ*3;
	if ((buf = malloc(len+1)) == NULL)
		err(1, NULL);
	memset(buf, 'A', len);

	if ((buf = extend(buf, &len)) == NULL ||
	    (in = fmemopen(buf, len, "r")) == NULL ||
	    (out = open_memstream(&outbuf, &outlen)) == NULL ||
	    (encrypt(in, out, key, &realmode)) == 0)
		err(1, NULL);
	fclose(out);

	guessmode = memcmp(outbuf+BLKSIZ, outbuf+BLKSIZ*2, BLKSIZ) == 0 ? ECB : CBC;

	puts(realmode == guessmode ? "success" : "failure");

	exit(0);
}
