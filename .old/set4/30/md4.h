#include <sys/types.h>

#define MD4_DIGEST_LENGTH	16

#define NSTATES			4
#define	BLKSIZ			64
#define PADSIZ			56

struct md4_ctx {
	uint32_t state[NSTATES];
	uint64_t count;
	uint8_t buf[BLKSIZ];
};

void md4_init(struct md4_ctx *);
void md4_update(struct md4_ctx *, uint8_t *, size_t);
void md4_final(uint8_t *, struct md4_ctx *);
