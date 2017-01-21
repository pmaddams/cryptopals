#include <sys/types.h>

#define NSTATE			4
#define	BLKSIZ			64

#define	DIGEST_LENGTH		16
#define	DIGEST_STRING_LENGTH	(DIGEST_LENGTH*2+1)

struct ctx {
	uint32_t state[NSTATE];
	uint64_t count;
	uint8_t buf[BLKSIZ];
};

void md4_init(struct ctx *);
void md4_update(struct ctx *, uint8_t *, size_t);
void md4_final(uint8_t *, struct ctx *);
