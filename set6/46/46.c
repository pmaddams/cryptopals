#include <sys/types.h>

#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#define BITS 1024

BIGNUM *
rsa_encrypt(RSA *rsa)
{
	const char *secret =
	    "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";
	BN_CTX *ctx;
	ssize_t len;
	char *buf;
	BIGNUM *res, *tmp;

	if ((ctx = BN_CTX_new()) == NULL)
		goto fail;
	BN_CTX_start(ctx);

	len = strlen(secret);
	if ((buf = malloc(len)) == NULL ||
	    (len = EVP_DecodeBlock(buf, secret, len)) == 0 ||

	    (res = BN_new()) == NULL ||
	    (tmp = BN_CTX_get(ctx)) == NULL ||

	    BN_bin2bn(buf, len, tmp) == NULL ||
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

char *
crack_rsa(RSA *rsa, BIGNUM *enc)
{
	BN_CTX *ctx;
	BIGNUM *tmp, *two, *factor, *lower, *upper, *mid;
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
	    (mid = BN_CTX_get(ctx)) == NULL ||

	    BN_copy(tmp, enc) == 0 ||
	    BN_set_word(two, 2) == 0 ||
	    BN_mod_exp(factor, two, rsa->e, rsa->n, ctx) == 0 ||
	    BN_zero(lower) == 0 ||
	    BN_copy(upper, rsa->n) == 0 ||

	    (buf = malloc(RSA_size(rsa))) == NULL)
		goto fail;

	for (;;) {
		if (BN_add(mid, lower, upper) == 0 ||
		    BN_div(mid, NULL, mid, two, ctx) == 0)
			goto fail;

		if (BN_cmp(lower, mid) == 0)
			break;

		if (BN_mod_mul(tmp, tmp, factor, rsa->n, ctx) == 0 ||
		    (even = is_plaintext_even(rsa, tmp, ctx)) == -1)
			goto fail;

		if (even) {
			if (BN_copy(upper, mid) == 0 ||
			    BN_add(upper, upper, BN_value_one()) == 0)
				goto fail;
		} else {
			if (BN_copy(lower, mid) == 0)
				goto fail;
		}

		if (BN_bn2bin(upper, buf) == 0)
			goto fail;
		print_hollywood_style(buf, BN_num_bytes(upper));
	};

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return buf;
fail:
	return NULL;
}

int
main(void)
{
	RSA *rsa;
	BIGNUM *f4, *enc;
	char *dec;

	if ((rsa = RSA_new()) == NULL ||
	    (f4 = BN_new()) == NULL ||

	    BN_set_word(f4, RSA_F4) == 0 ||
	    RSA_generate_key_ex(rsa, BITS, f4, NULL) == 0 ||

	    (enc = rsa_encrypt(rsa)) == NULL ||
	    (dec = crack_rsa(rsa, enc)) == NULL)
		err(1, NULL);

	puts(dec);

	exit(0);
}
