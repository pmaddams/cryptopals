#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define BLKSIZ 16

bool
is_valid(uint8_t *buf, size_t len)
{
	bool res;
	uint8_t *p, pad;

	res = false;

	if (len % BLKSIZ)
		goto done;

	buf += len - BLKSIZ;
	len = BLKSIZ;

	while (isprint(*buf)) {
		buf++;
		len--;
	}
	p = buf;

	if (len == 0)
		goto done;

	pad = len;
	while (len--)
		if (*buf++ != pad)
			goto done;

	*p = '\0';
	res = true;
done:
	return res;
}

int
main(int argc, char **argv)
{
	char s[] = "ICE ICE BABY\x04\x04\x04\x04";
	puts(is_valid(s, strlen(s)) ? "valid" : "invalid");
	return 0;
}
