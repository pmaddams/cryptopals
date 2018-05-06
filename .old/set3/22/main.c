#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "mt.h"

int
main(void)
{
	struct mt mt;
	time_t t, i;
	uint32_t x;

	time(&t);
	t += 40 + arc4random_uniform(960);

	printf("%u\n", t);

	mt_init(&mt, t);
	x = mt_rand(&mt);

	t += 40 + arc4random_uniform(960);

	for (i = 0; i <= 1000; i++) {
		mt_init(&mt, t-i);
		if (mt_rand(&mt) == x)
			break;
	}

	printf("%u\n", t-i);

	exit(0);
}
