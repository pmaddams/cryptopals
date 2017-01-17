#include <stdio.h>

#include "mt.h"

int
main(void)
{
	struct mt mt;

	mt_init(&mt, 5489);

	printf("%u\n", mt_rand(&mt));

	return 0;
}
