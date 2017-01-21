#include <stdio.h>
#include <stdlib.h>

#include "md4.h"

void
putx(uint8_t *buf, size_t len)
{
	while (len--)
		printf("%02x", *buf++);
	putchar('\n');
}

int
main(void)
{
	struct md4_ctx ctx;
	uint8_t buf[DIGEST];

	md4_init(&ctx);
	md4_update(&ctx, "hello world", 11);
	md4_final(buf, &ctx);

	putx(buf, DIGEST);

	exit(0);
}
