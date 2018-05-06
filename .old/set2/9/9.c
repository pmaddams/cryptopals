#include <stdio.h>

#define BLKSIZ 20

int
main(void)
{
	char buf[BLKSIZ], pad;
	size_t len;

	while ((len = fread(buf, 1, BLKSIZ, stdin)) == BLKSIZ)
		fwrite(buf, BLKSIZ, 1, stdout);
	fwrite(buf, len, 1, stdout);

	for (pad = BLKSIZ-len; len < BLKSIZ; len++)
		printf("\\x%02x", pad);
	putchar('\n');

	return 0;
}
