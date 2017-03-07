#include <sys/types.h>

#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#define BITS 1024

const char *data = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";

BIGNUM *
rsa_encrypt_b64(RSA *rsa, char *buf)
{
	BN_CTX *ctx;
	ssize_t buflen, tmplen;
	char *tmpbuf;
	BIGNUM *res, *tmp;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	buflen = strlen(buf);
	if ((tmpbuf = malloc(buflen)) == NULL ||
	    (tmplen = EVP_DecodeBlock(tmpbuf, buf, buflen)) == 0 ||

	    (res = BN_new()) == NULL ||
	    (tmp = BN_CTX_get(ctx)) == NULL ||

	    BN_bin2bn(tmpbuf, tmplen, tmp) == NULL ||
	    BN_mod_exp(res, tmp, rsa->e, rsa->n, ctx) == 0)
		goto fail;

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return res;
fail:
	return NULL;
}

int
is_plaintext_even(RSA *rsa, BIGNUM *enc, BN_CTX *ctx)
{
	static BIGNUM *tmp;

	if (tmp == NULL)
		if ((tmp = BN_CTX_get(ctx)) == NULL)
			goto fail;

	if (BN_mod_exp(tmp, enc, rsa->d, rsa->n, ctx) == 0)
		goto fail;

	return !BN_is_odd(tmp);
fail:
	return -1;
}

void
print_hollywood_style(char *buf, size_t len)
{
	char c;

	while (len--)
		if (isprint(c = *buf++))
			putchar(c);
		else
			putchar('?');
	putchar('\n');
}

int
crack_rsa(RSA *rsa, BIGNUM *enc)
{
	BN_CTX *ctx;
	BIGNUM *tmp, *two, *factor, *lower, *upper;
	char *buf;
	int even;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	if ((tmp = BN_CTX_get(ctx)) == NULL ||
	    (two = BN_CTX_get(ctx)) == NULL ||
	    (factor = BN_CTX_get(ctx)) == NULL ||
	    (lower = BN_CTX_get(ctx)) == NULL ||
	    (upper = BN_CTX_get(ctx)) == NULL ||

	    BN_copy(tmp, enc) == 0 ||
	    BN_set_word(two, 2) == 0 ||
	    BN_mod_exp(factor, two, rsa->e, rsa->n, ctx) == 0 ||
	    BN_zero(lower) == 0 ||
	    BN_copy(upper, rsa->n) == 0 ||

	    (buf = malloc(RSA_size(rsa))) == NULL)
		goto fail;

	while (BN_cmp(lower, upper)) {
		if (BN_mod_mul(tmp, tmp, factor, rsa->n, ctx) == 0 ||
		    (even = is_plaintext_even(rsa, tmp, ctx)) == -1)
			goto fail;

		if (even) {
			if (BN_add(upper, lower, upper) == 0 ||
			    BN_div(upper, NULL, upper, two, ctx) == 0)
				goto fail;
		} else {
			if (BN_add(lower, lower, upper) == 0 ||
			    BN_div(lower, NULL, lower, two, ctx) == 0)
				goto fail;
		}

		if (BN_bn2bin(upper, buf) == 0)
			goto fail;
		print_hollywood_style(buf, BN_num_bytes(upper));
	};

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	free(buf);

	return 1;
fail:
	return 0;
}

int
main(void)
{
	RSA *rsa;
	BIGNUM *f4, *enc;

	if ((rsa = RSA_new()) == NULL ||
	    (f4 = BN_new()) == NULL ||

	    BN_set_word(f4, RSA_F4) == 0 ||
	    RSA_generate_key_ex(rsa, BITS, f4, NULL) == 0 ||

	    (enc = rsa_encrypt_b64(rsa, (char *) data)) == NULL ||

	    crack_rsa(rsa, enc) == 0)
		err(1, NULL);

	exit(0);
}
