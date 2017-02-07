#include <search.h>
#include <sha2.h>
#include <stdio.h>

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

int
dict_init(char *path)
{
	FILE *fp;
	size_t nlines;

	if ((fp = fopen(path, "r")) == NULL ||
	    (nlines = count_lines(fp)) == 0 ||
	    hcreate(nlines) == 0)
		goto fail;
}
