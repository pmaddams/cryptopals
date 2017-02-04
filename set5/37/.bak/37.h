#include <sys/types.h>

#include <openssl/bn.h>

#define PORT		12345

#define USERNAME	"admin@secure.net"

char *make_hmac(char *, char *);
char *srecv(int);
int ssend(int, char *);
int ssendf(int, char *, ...);
