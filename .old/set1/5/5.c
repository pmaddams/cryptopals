#include <err.h>
#include <stdio.h>
#include <string.h>

#define FILENAME	"DATA"

#define KEY		"ICE"

int
main(void)
{
	FILE *fp;
	size_t i, len;
	int c;

	if ((fp = fopen(FILENAME, "r")) == NULL)
		err(1, NULL);

	len = strlen(KEY);
	for (i = 0; (c = getc(fp)) != EOF; i++)
		printf("%02x", c ^ KEY[i % len]);
	putchar('\n');

	return 0;
}
