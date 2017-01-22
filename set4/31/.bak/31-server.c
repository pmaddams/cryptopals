#include <sys/types.h>

#include <err.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BLKSIZ		64
#define SLEEPTIME	50 /* ms */
#define FILENAME	"TEST"

extern char **environ;

enum _codes {
	OK,
	BAD
};

const char *status[2] = {
	"200 OK",
	"400 Bad Request"
};

void
header(int code)
{
	printf("Status: %s\r\n", status[code]);
	printf("Content-type: text/html\r\n\r\n");
}

int
get_query(char **fnp, char **sigp)
{
	char *qfield, *ffield, *sfield,
	    *q, *fn, *sig;
	size_t tmplen, fnlen, siglen;

	qfield = "QUERY_STRING=";
	ffield = "file=";
	sfield = "signature=";

	q = NULL;
	tmplen = strlen(qfield);
	while (*environ) {
		if (strncmp(*environ, qfield, tmplen) == 0) {
			q = *environ + tmplen;
			break;
		}
		environ++;
	}
	if (q == NULL)
		goto fail;

	if ((fn = strstr(q, ffield)) == NULL)
		goto fail;
	fn += strlen(ffield);
	for (fnlen = 0; fn[fnlen] != '\0' && fn[fnlen] != '&'; fnlen++)
		continue;

	if ((sig = strstr(q, sfield)) == NULL)
		goto fail;
	sig += strlen(sfield);
	for (siglen = 0; sig[siglen] != '\0' && sig[siglen] != '&'; siglen++)
		continue;

	fn[fnlen] = '\0';
	sig[siglen] = '\0';

	*fnp = fn;
	*sigp = sig;

	return 1;
fail:
	return 0;
}

int
sha1_hmac(char *res, FILE *fp)
{
	const char *key = "YELLOW SUBMARINE";
	uint8_t ipad[BLKSIZ], opad[BLKSIZ],
	    hash1[SHA1_DIGEST_LENGTH],
	    hash2[SHA1_DIGEST_LENGTH],
	    buf[BUFSIZ];
	size_t i, keylen, nr;
	SHA1_CTX ctx;

	memset(ipad, '\x5c', BLKSIZ);
	memset(opad, '\x36', BLKSIZ);

	keylen = strlen(key);
	for (i = 0; i < keylen; i++) {
		ipad[i] ^= key[i];
		opad[i] ^= key[i];
	}

	SHA1Init(&ctx);
	SHA1Update(&ctx, ipad, BLKSIZ);
	while ((nr = fread(buf, 1, BUFSIZ, fp)) > 0)
		SHA1Update(&ctx, buf, nr);
	if (ferror(fp))
		goto fail;
	SHA1Final(hash1, &ctx);

	SHA1Init(&ctx);
	SHA1Update(&ctx, opad, BLKSIZ);
	SHA1Update(&ctx, hash1, SHA1_DIGEST_LENGTH);
	SHA1Final(hash2, &ctx);

	for (i = 0; i < SHA1_DIGEST_LENGTH; i++)
		snprintf(res+i*2, 3, "%02x", hash2[i]);

	return 1;
fail:
	return 0;
}

int
insecure_compare(char *sig, char *hmac)
{
	static struct timespec ts;

	if (ts.tv_nsec == 0)
		ts.tv_nsec = SLEEPTIME*1000000;

	while (*sig == *hmac) {
		nanosleep(&ts, NULL);
		if (*sig == '\0')
			return 1;
		sig++;
		hmac++;
	}

	return 0;
}

int
main(void)
{
	FILE *fp;
	char *fn, *sig,
	    hmac[SHA1_DIGEST_STRING_LENGTH];
	int rv;

	if ((fp = fopen(FILENAME, "r")) == NULL ||
	    sha1_hmac(hmac, fp) == 0)
		err(1, NULL);

	rv = BAD;
	if (get_query(&fn, &sig) == 1 &&
	    insecure_compare(fn, FILENAME) == 1 &&
	    insecure_compare(sig, hmac) == 1)
		rv = OK;

	header(rv == OK ? OK : BAD);
	printf("<!-- %s: %s -->\r\n",
	    (rv == OK ? "SUCCESS" : "FAILURE"), hmac);

	exit(0);
}
