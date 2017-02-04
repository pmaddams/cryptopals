#include <sys/types.h>

#include <openssl/bn.h>

#define PORT		12345

#define USERNAME	"admin@secure.net"

char *input(void);
char *make_hmac(char *, char *);
char *make_shared_k(BIGNUM *);
void print(char *);
char *srecv(int);
int ssend(int, char *);
int ssendf(int, char *, ...);
