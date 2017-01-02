#include <ctype.h>
#include <stdio.h>

#define MINIMUM(a, b) ((a)<(b)?(a):(b))

void
xor(uint8_t *b1, uint8_t *b2, size_t len)
{
	while (len--)
		*b1++ ^= *b2++;
}

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

int
main(void)
{
	char s1[] = "1c0111001f010100061a024b53535009181c",
	    s2[] = "686974207468652062756c6c277320657965";
	size_t i, l1, l2, len;

	xtoa(s1, &l1);
	xtoa(s2, &l2);

	len = MINIMUM(l1, l2);
	xor(s1, s2, len);

	for (i = 0; i < len; i++)
		printf("%hhx", s1[i]);
	putchar('\n');

	return 0;
}
