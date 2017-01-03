#include <ctype.h>
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tab.h"

char *
xtoa(char *s, size_t *lenp)
{
	int i, j, k;
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
		if (isprint(c = *buf++))
			switch (c) {
			case ' ':
				res += tab[0];
				break;
			case 'A'...'Z':
				c = c - 'A' + 'a';
				/* FALLTHROUGH */
			case 'a'...'z':
				res += tab[1 + c - 'a'];
				break;
			default:
				break;
			}

	return res;
}

int
main(void)
{
	float scr, best;
	char *buf, *lbuf, *cp, *found;
	size_t len;
	int c;

	best = 0.;
	lbuf = found = NULL;

	while (buf = fgetln(stdin, &len)) {
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

		for (c = 0; c <= UINT8_MAX; c++) {
			memcpy(cp, buf, len);
			xor(cp, c, len);
			if ((scr = score(cp, len)) > best) {
				free(found);
				if ((found = strdup(cp)) == NULL)
					err(1, NULL);
				best = scr;
			}
		}
		free(cp);
	}
	free(lbuf);

	if (best == 0.)
		errx(1, "no match found");

	puts(found);

	exit(0);
}
