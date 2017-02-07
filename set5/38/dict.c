#include <sys/types.h>

#include <search.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t
count_lines(FILE *fp)
{
	size_t nlines, len;

	if (fseek(fp, 0, SEEK_SET) != 0)
		goto fail;

	for (nlines = 0; fgetln(fp, &len); nlines++)
		continue;

	if (ferror(fp) ||
	    fseek(fp, 0, SEEK_SET) != 0)
		goto fail;

	return nlines;
fail:
	return 0;
}

char *
sha256(char *salt, char *password)
{
	SHA2_CTX sha2ctx;

	SHA256Init(&sha2ctx);
	SHA256Update(&sha2ctx, salt, strlen(salt));
	SHA256Update(&sha2ctx, password, strlen(password));

	return SHA256End(&sha2ctx, NULL);
}

int
dict_init(char *path, char *salt)
{
	FILE *fp;
	size_t nlines, len;
	char *buf, *key, *data;
	ENTRY entry, *found;

	if ((fp = fopen(path, "r")) == NULL ||
	    (nlines = count_lines(fp)) == 0 ||
	    hcreate(nlines) == 0)
		goto fail;

	while (buf = fgetln(fp, &len)) {
		if (buf[len-1] == '\n')
			len--;
		if ((data = malloc(len+1)) == NULL)
			goto fail;
		memcpy(data, buf, len);
		data[len] = '\0';

		if ((key = sha256(salt, data)) == NULL)
			goto fail;

		entry.key = key;
		entry.data = data;

		if ((found = hsearch(entry, ENTER)) == NULL)
			goto fail;
	}

	return 1;
fail:
	return 0;
}
