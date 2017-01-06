#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

const char secret[] =
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK";

int
encrypt(FILE *in, FILE *out)
{
	static char key[16];
	static BIO *cip;
	BIO *bio;
	char buf[BUFSIZ];
	int nr;

	while (*key == '\0')
		arc4random_buf(key, 16);

	if (cip == NULL) {
		if ((cip = BIO_new(BIO_f_cipher())) == NULL)
			goto fail;
		BIO_set_cipher(cip, EVP_aes_128_ecb(), key, NULL, 1);
	}

	if ((bio = BIO_new_fp(in, BIO_NOCLOSE)) == NULL)
		goto fail;

	BIO_push(cip, bio);

	while ((nr = BIO_read(cip, buf, BUFSIZ)) > 0)
		if (fwrite(buf, nr, 1, out) < 1)
			goto fail;

	BIO_pop(bio);
	BIO_free(bio);

	return 1;
fail:
	return 0;
}

size_t
crack_blksiz(void)
{
	return 0;
}

int
main(void)
{
	return 0;
}
