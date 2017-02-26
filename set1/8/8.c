#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLKSIZ 16

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

int
main(void)
{
	char *buf, *lbuf, *found;
	size_t i, j, len, foundln;
	int score, best;

	best = 0;
	lbuf = found = NULL;

	while (buf = fgetln(stdin, &len)) {
		if (buf[len-1] == '\n')
			buf[len-1] = '\0';
		else {
			if ((lbuf = malloc(len+1)) == NULL)
				err(1, NULL);
			memcpy(lbuf, buf, len);
			lbuf[len] = '\0';
			buf = lbuf;
		}

		xtoa(buf, &len);

		for (score = 0, i = 0; i+BLKSIZ*2 <= len; i += BLKSIZ)
			for (j = i+BLKSIZ; j+BLKSIZ <= len; j += BLKSIZ)
				if (memcmp(buf+i, buf+j, BLKSIZ) == 0)
					score++;

		if (score > best) {
			best = score;
			if ((found = realloc(found, len)) == NULL)
				err(1, NULL);
			memcpy(found, buf, len);
			foundln = len;
		}
	}
	free(lbuf);

	for (i = 0; i < foundln; i++)
		printf("%02hhx", found[i]);
	putchar('\n');

	exit(0);
}
