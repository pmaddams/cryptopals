#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "mt.h"

#define KEY 12345

int
main(void)
{
	size_t len;
	char *buf, *enc, *dec;
	uint16_t guess;
	bool found;

	len = arc4random_uniform(14) + 14;

	if ((buf = malloc(len)) == NULL)
		err(1, NULL);

	arc4random_buf(buf, len);
	memset(buf+len-14, 'A', 14);

	if ((enc = mt_crypt(buf, len, KEY)) == NULL)
		err(1, NULL);

	for (found = false, guess = 0;; guess++) {
		if ((dec = mt_crypt(enc, len, guess)) == NULL)
			err(1, NULL);
		if (memcmp(dec+len-BLKSIZ, "AAAA", BLKSIZ) == 0) {
			found = true;
			break;
		}
		if (guess == UINT16_MAX)
			break;
	}

	if (found)
		printf("Found key %u\n", guess);

	exit(0);
}
