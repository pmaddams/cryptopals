#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#define USER	1
#define ADMIN	2

struct profile {
	char *email;
	int uid;
	int role;
};

int
is_valid(char *email)
{
	char c;
	int ctr, nchar, at, dot;

	for (ctr = nchar = at = dot = 0; c = *email++; nchar++)
		switch (c) {
		case '@':
			if (!ctr || at)
				goto fail;
			at = 1;
			ctr = 0;
			break;
		case '.':
			if (!ctr)
				goto fail;
			if (at)
				dot = 1;
			ctr = 0;
			break;
		case '=':
		case '&':
			goto fail;
		case 'A'...'Z':
		case 'a'...'z':
		case '0'...'9':
		case '-':
			ctr++;
			break;
		default:
			if (at || isspace(c) || !isprint(c))
				goto fail;
			ctr++;
			break;
		}

	if (!at || !dot || nchar > 254)
		goto fail;

	return 1;
fail:
	return 0;
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
			if ((email = strdup(field+6)) == NULL)
				goto fail;
		} else if (strncmp(field, "uid=", 4) == 0) {
			uid = strtonum(field+4, 1, 1000, &errstr);
			if (errstr)
				goto fail;
		} else if (strncmp(field, "role=", 5) == 0) {
			field += 5;
			if (strcmp(field, "admin"))
				role = ADMIN;
			else if (strcmp(field, "user"))
				role = USER;
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
	return NULL;
fail:
	free(cp);
	free(email);
	return NULL;
}

int
main(void)
{
	return 0;
}
