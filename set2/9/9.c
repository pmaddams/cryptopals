#include <stdio.h>

#define BLKSIZ 20

int
main(void)
{
	char blk[BLKSIZ], pad;
	size_t len;

	while ((len = fread(blk, 1, BLKSIZ, stdin)) == BLKSIZ)
		fwrite(blk, BLKSIZ, 1, stdout);
	fwrite(blk, len, 1, stdout);

	for (pad = BLKSIZ-len; len < BLKSIZ; len++)
		printf("\\x%02x", pad);
	putchar('\n');

	return 0;
}
