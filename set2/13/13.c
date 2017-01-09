#include <ctype.h>
#include <err.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define BLKSIZ	16

#define USER	1
#define ADMIN	2

#define DECRYPT	0
#define ENCRYPT	1

struct profile {
	char *email;
	int uid;
	int role;
};

bool
is_valid(char *email)
{
	bool res;
	int ctr, nchr, at, dom;
	char c;

	for (res = false, ctr = nchr = at = dom = 0; c = *email++; nchr++)
		switch (c) {
		case '@':
			if (!ctr || at)
				goto done;
			at = 1;
			ctr = 0;
			break;
		case '.':
			if (!ctr)
				goto done;
			if (at)
				dom = 1;
			ctr = 0;
			break;
		case '=':
		case '&':
			goto done;
		case 'A'...'Z':
		case 'a'...'z':
		case '0'...'9':
		case '-':
			ctr++;
			break;
		default:
			if (at || isspace(c) || !isprint(c))
				goto done;
			ctr++;
			break;
		}

	if (!at || !dom || nchr > 254)
		goto done;

	res = true;
done:
	return res;
}

char *
profile_for(char *email)
{
	char *res;

	if (!is_valid(email) ||
	    asprintf(&res, "email=%s&uid=10&role=user", email) == -1)
		goto fail;

	return res;
fail:
	return NULL;
}

struct profile *
parse(char *s)
{
	char *cp, *field, *email;
	int uid, role;
	const char *errstr;
	struct profile *profile;

	if ((cp = strdup(s)) == NULL)
		goto fail;

	email = NULL;
	uid = role = 0;

	while (field = strsep(&cp, "&"))
		if (strncmp(field, "email=", 6) == 0) {
			field += 6;
			if (!is_valid(field) ||
			    (email = strdup(field)) == NULL)
				goto fail;
		} else if (strncmp(field, "uid=", 4) == 0) {
			field += 4;
			uid = strtonum(field, 1, 1000, &errstr);
			if (errstr)
				goto fail;
		} else if (strncmp(field, "role=", 5) == 0) {
			field += 5;
			if (strcmp(field, "user"))
				role = USER;
			else if (strcmp(field, "admin"))
				role = ADMIN;
			else
				goto fail;
		} else
			goto fail;

	if (email == NULL || uid == 0 || role == 0 ||
	    (profile = malloc(sizeof(*profile))) == NULL)
		goto fail;

	profile->email = email;
	profile->uid = uid;
	profile->role = role;

	free(cp);
	return profile;
fail:
	free(cp);
	free(email);
	return NULL;
}

uint8_t *
ecb_crypt(uint8_t *in, size_t inlen, size_t *outlenp, int enc)
{
	static uint8_t key[BLKSIZ];
	EVP_CIPHER_CTX ctx;
	uint8_t *out;
	int outlen, tmplen;

	while (*key == '\0')
		arc4random_buf(key, BLKSIZ);

	EVP_CIPHER_CTX_init(&ctx);

	if ((out = malloc(inlen+BLKSIZ)) == NULL ||
	    EVP_CipherInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key, NULL, enc) == 0 ||
	    EVP_CipherUpdate(&ctx, out, &outlen, in, inlen) == 0 ||
	    EVP_CipherFinal_ex(&ctx, out+outlen, &tmplen) == 0)
		goto fail;

	EVP_CIPHER_CTX_cleanup(&ctx);

	outlen += tmplen;
	if (outlenp != NULL)
		*outlenp = outlen;

	return out;
fail:
	return NULL;
}

char
munge(char *attack, char **resp)
{
	char *munged, c, c1;
	size_t i, len;

	if (resp == NULL ||
	    (len = strlen(attack)) != BLKSIZ ||
	    (munged = malloc(len+1)) == NULL)
		goto fail;

	for (c = 0; c < CHAR_MAX; c++) {
		memcpy(munged, attack, len);
		for (i = 0; i < len; i++) {
			c1 = (munged[i] ^= c);
			if (c1 == '&' || c1 == '=' ||
			    isspace(c1) || !isprint(c1))
				break;
		}
		if (i == len)
			goto done;
	}
	goto fail;
done:
	munged[len] = '\0';

	*resp = munged;
	return c;
fail:
	free(munged);
	return -1;
}

int
main(void)
{
	char c, *munged;

	if ((c = munge("role=admin&uid=1", &munged)) == -1)
		errx(1, "can't munge attack");

	puts(munged);

	exit(0);
}
