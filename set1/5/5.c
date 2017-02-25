#include <stdio.h>
#include <string.h>

#define KEY "ICE"

int
main(void)
{
	size_t i, len;
	int c;

	len = strlen(KEY);
	for (i = 0; (c = getchar()) != EOF; i++)
		printf("%02x", c ^ KEY[i % len]);
	putchar('\n');

	return 0;
}
