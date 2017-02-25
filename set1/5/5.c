#include <stdio.h>
#include <string.h>

#define KEY "ICE"

int
main(void)
{
	size_t i, len;
	int c;

	i = 0;
	len = strlen(KEY);

	while ((c = getchar()) != EOF)
		printf("%02x", c ^ KEY[i++ % len]);
	putchar('\n');

	return 0;
}
