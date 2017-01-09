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
			if (at) /* || isspace(c) || !isprint(c)) */
			/* Inadequate input validation required */
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
			if (strcmp(field, "user") == 0)
				role = USER;
			else if (strcmp(field, "admin") == 0)
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

char *
padded(char *s)
{
	size_t len, newlen;
	char *buf, pad;

	len = strlen(s);
	newlen = (len/BLKSIZ+1)*BLKSIZ;
	pad = newlen-len;

	if ((buf = malloc(newlen+1)) == NULL)
		goto done;

	memcpy(buf, s, len);
	while (len <= newlen)
		buf[len++] = pad;
	buf[len] = '\0';
done:
	return buf;
}

int
main(void)
{
	char *attack, buf[BUFSIZ], *legit, *enc1, *enc2, *dec;
	size_t declen;
	struct profile *profile;

	if ((attack = padded("admin")) == NULL)
		err(1, NULL);

	buf[0] = '\0';
	strlcpy(buf, "XXXXXXXXXX", BUFSIZ);
	strlcat(buf, attack, BUFSIZ);
	strlcat(buf, "@gmail.com", BUFSIZ);
	free(attack);

	if ((legit = profile_for("cheap_viagra_online@gmail.com")) == NULL ||
	    (enc1 = ecb_crypt(legit, strlen(legit), NULL, ENCRYPT)) == NULL ||
	    (attack = profile_for(buf)) == NULL ||
	    (enc2 = ecb_crypt(attack, strlen(attack), NULL, ENCRYPT)) == NULL)
		err(1, NULL);

	memcpy(buf, enc1, BLKSIZ*3);
	memcpy(buf+BLKSIZ*3, enc2+BLKSIZ, BLKSIZ);

	if ((dec = ecb_crypt(buf, BLKSIZ*4, &declen, DECRYPT)) == NULL)
		err(1, NULL);
	dec[declen] = '\0';

	if ((profile = parse(dec)) == NULL)
		err(1, NULL);

	printf("email: %s\n", profile->email);
	printf("uid: %d\n", profile->uid);
	printf("role: %s\n", profile->role == ADMIN ? "admin" : "user");

	exit(0);
}
