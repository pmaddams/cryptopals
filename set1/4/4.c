#include <sys/types.h>

#include <ctype.h>
#include <err.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freq.h"

#define FILENAME "DATA"

char *
xtoa(char *s, size_t *lenp)
{
	size_t i, j, k;
	char c;
	static char buf[3];

	for (i = j = 0;; i++) {
		for (k = 0; k < 2;)
			if (isxdigit(c = s[j+k]))
				buf[k++] = c;
			else if (c != '\0')
				j++;
			else
				goto done;

		s[i] = strtol(buf, NULL, 16);
		j += k;
	}
done:
	s[i] = '\0';
	if (lenp != NULL)
		*lenp = i;
	return s;
}

void
xor(uint8_t *buf, uint8_t c, size_t len)
{
	while (len--)
		*buf++ ^= c;
}

float
score(uint8_t *buf, size_t len)
{
	float res;
	uint8_t c;

	for (res = 0.; len--;)
		switch (c = *buf++) {
		case ' ':
			res += freq[0];
			break;
		case 'A'...'Z':
			c = c - 'A' + 'a';
			/* FALLTHROUGH */
		case 'a'...'z':
			res += freq[1 + c - 'a'];
			break;
		default:
			break;
		}

	return res;
}

int
main(void)
{
	FILE *fp;
	float cur, best;
	char *buf, *lbuf, *cp, *found;
	size_t len;
	uint8_t c;

	best = 0.;
	lbuf = found = NULL;

	if ((fp = fopen(FILENAME, "r")) == NULL)
		err(1, NULL);

	while (buf = fgetln(fp, &len)) {
		if (buf[len-1] == '\n')
			buf[--len] = '\0';
		else {
			if ((lbuf = malloc(len+1)) == NULL)
				err(1, NULL);
			memcpy(lbuf, buf, len);
			lbuf[len] = '\0';
			buf = lbuf;
		}

		xtoa(buf, &len);

		if ((cp = malloc(len+1)) == NULL)
			err(1, NULL);
		cp[len] = '\0';

		for (c = 0;; c++) {
			memcpy(cp, buf, len);
			xor(cp, c, len);
			if ((cur = score(cp, len)) > best) {
				best = cur;
				free(found);
				if ((found = strdup(cp)) == NULL)
					err(1, NULL);
			}
			if (c == UINT8_MAX)
				break;
		}
		free(cp);
	}
	free(lbuf);

	if (best == 0.)
		errx(1, "no match found");

	puts(found);

	exit(0);
}
