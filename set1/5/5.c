#include <stdio.h>
#include <string.h>

#define KEY "ICE"

int
encrypt(int c)
{
	static size_t i, len;

	if (len == 0)
		len = strlen(KEY);

	if (c != EOF)
		c ^= KEY[i++ % len];

	return c;
}

int
main(void)
{
	int c;

	while ((c = encrypt(getchar())) != EOF)
		printf("%02x", c);
	putchar('\n');

	return 0;
}
