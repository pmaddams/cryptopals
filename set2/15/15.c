#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define BLKSIZ 16

void
proc(uint8_t *buf, size_t *lenp)
{
	size_t i, j;
	char tmp[3];

	for (i = j = 0; i < *lenp;)
		switch (buf[i]) {
		case '\\':
			if (buf[i+1] == 'x') {
				i += 2;
				if (i < *lenp && isxdigit(buf[i])) {
					memset(tmp, '\0', 3);
					tmp[0] = buf[i++];
					if (i < *lenp && isxdigit(buf[i]))
						tmp[1] = buf[i++];
					buf[j++] = strtol(tmp, NULL, 16);
				}
			} else if (buf[i+1] == '0') {
				i += 2;
				if (i < *lenp && isdigit(buf[i])) {
					memset(tmp, '\0', 3);
					tmp[0] = buf[i++];
					if (i < *lenp && isdigit(buf[i]))
						tmp[1] = buf[i++];
					buf[j++] = strtol(tmp, NULL, 8);
					tmp[0] = '\0';
				}
			}
			break;
		default:
			buf[j++] = buf[i++];
			break;
		}

	if (lenp != NULL)
		*lenp = j;
	buf[j] = '\0';
}

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
	char *s;
	size_t len;

	while (argc > 1) {
		s = argv[1];
		len = strlen(s);
		
		proc(s, &len);
		printf("%s: %s\n", s, is_valid(s, len) ? "valid" : "invalid");

		argc--;
		argv++;
	}

	return 0;
}
