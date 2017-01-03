#include <ctype.h>
#include <stdio.h>

#define MINIMUM(a, b) ((a)<(b)?(a):(b))

char s1[] = "1c0111001f010100061a024b53535009181c";
char s2[] = "686974207468652062756c6c277320657965";

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
	*lenp = i;
	return s;
}

void
xor(uint8_t *b1, uint8_t *b2, size_t len)
{
	while (len--)
		*b1++ ^= *b2++;
}

int
main(void)
{
	size_t i, l1, l2;

	xtoa(s1, &l1);
	xtoa(s2, &l2);

	l1 = MINIMUM(l1, l2);
	xor(s1, s2, l1);

	for (i = 0; i < l1; i++)
		printf("%hhx", s1[i]);
	putchar('\n');

	return 0;
}
