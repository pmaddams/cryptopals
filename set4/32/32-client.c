#include <sys/time.h>

#include <openssl/ssl.h>

#include <err.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define HOST		"localhost"
#define PORT		"443"
#define RESOURCE	"/cgi-bin/32-server"
#define FILENAME	"TEST"

#define HEXCHARS	"0123456789abcdef"

long
how_long(struct timespec *start, struct timespec *end)
{
	timespecsub(end, start, end);

	return (long) end->tv_sec*1000 + end->tv_nsec/1000000;
}

int
main(void)
{
	SSL_CTX *ctx;
	BIO *conn;
	char buf[BUFSIZ], *attack, *hmac;
	size_t i, j, len;
	ssize_t nr;
	struct timespec start, end;
	long elapsed, best;
	int match, found;

	SSL_library_init();
	if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL ||
	    (conn = BIO_new_ssl_connect(ctx)) == NULL)
		err(1, NULL);

	BIO_set_conn_hostname(conn, HOST ":" PORT);
	if (asprintf(&attack, "%s?file=%s&signature=", RESOURCE, FILENAME) < 0)
		err(1, NULL);

	len = strlen(attack);
	if ((attack = realloc(attack, len+SHA1_DIGEST_STRING_LENGTH)) == NULL)
		err(1, NULL);
	hmac = attack+len;
	memset(hmac, 0, SHA1_DIGEST_STRING_LENGTH);

	setvbuf(stdout, NULL, _IONBF, 0);
	for (i = 0; i < SHA1_DIGEST_STRING_LENGTH-2; i++) {
		for (best = 0L, match = 0, j = 0; j < 16; j++) {
			hmac[i] = HEXCHARS[j];

			BIO_reset(conn);
			if ((BIO_do_connect(conn)) <= 0)
				err(1, NULL);

			clock_gettime(CLOCK_MONOTONIC, &start);
			BIO_printf(conn, "GET %s HTTP/1.1\r\n", attack);
			BIO_puts(conn,
			    "Host: " HOST "\r\n"
			    "Connection: close\r\n"
			    "\r\n"
			);

			if ((nr = BIO_read(conn, buf, BUFSIZ)) <= 0)
				err(1, NULL);
			clock_gettime(CLOCK_MONOTONIC, &end);

			if ((elapsed = how_long(&start, &end)) > best) {
				best = elapsed;
				match = HEXCHARS[j];
			}
		}
		hmac[i] = match;
		putchar(match);
	}

	for (found = 0, j = 0; j < 16; j++) {
		hmac[SHA1_DIGEST_STRING_LENGTH-2] = HEXCHARS[j];

		BIO_reset(conn);
		if ((BIO_do_connect(conn)) <= 0)
			err(1, NULL);

		BIO_printf(conn, "GET %s HTTP/1.1\r\n", attack);
		BIO_puts(conn,
		    "Host: " HOST "\r\n"
		    "Connection: close\r\n"
		    "\r\n"
		);

		if ((nr = BIO_read(conn, buf, BUFSIZ)) <= 0)
			err(1, NULL);
		buf[nr-1] = '\0';

		if (strstr(buf, "200 OK") != NULL) {
			found = 1;
			putchar(HEXCHARS[j]);
			break;
		}
	}
	putchar('\n');

	puts(found ? hmac : "not found");

	exit(0);
}
