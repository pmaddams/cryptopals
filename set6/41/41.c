#include <sha2.h>
#include <time.h>

#include <openssl/bn.h>

#define HASHSIZE	101
#define TIMEOUT		3600

struct message {
	time_t timestamp;
	char *text;
};

struct entry {
	time_t timestamp;
	char *hash;
	struct entry *next;
};

struct entry *tab[HASHSIZE];
