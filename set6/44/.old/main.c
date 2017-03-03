#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/dsa.h>

#include "44.h"

int
main(void)
{
	FILE *fp;
	struct data data;

	if ((fp = fopen(FILENAME, "r")) == NULL ||
	    load_data(&data, fp) == 0)
		err(1, NULL);

	exit(0);
}
