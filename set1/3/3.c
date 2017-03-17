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

int
getx(FILE *fp)
{
	int i, c;
	static char buf[3];

	for (i = 0; i < 2;)
		if (isxdigit(c = getc(fp)))
			buf[i++] = c;
		else if (c == EOF)
			return EOF;

	return strtol(buf, NULL, 16);
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
	FILE *fp, *memstream;
	char *buf, *cp;
	size_t len;
	int c, found;
	float cur, best;

	if ((fp = fopen(FILENAME, "r")) == NULL ||
	    (memstream = open_memstream(&buf, &len)) == NULL)
		err(1, NULL);

	while ((c = getx(fp)) != EOF)
		putc(c, memstream);
	fclose(memstream);

	if ((cp = malloc(len)) == NULL)
		err(1, NULL);

	for (best = 0., c = 0; c <= UINT8_MAX; c++) {
		memcpy(cp, buf, len);
		xor(cp, c, len);
		if ((cur = score(cp, len)) > best) {
			best = cur;
			found = c;
		}
	}

	if (best == 0.)
		errx(1, "no match found");

	xor(buf, found, len);
	puts(buf);
 
	exit(0);
}
