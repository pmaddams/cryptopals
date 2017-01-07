#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

struct profile {
	char *email;
	int uid;
	enum {
		USER,
		ADMIN
	} role;
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
			if (at)
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
