#include <sys/types.h>

#define NSTATE	4
#define	BLKSIZ	64
#define DIGEST	16

struct md4_ctx {
	uint32_t state[NSTATE];
	uint64_t count;
	uint8_t buf[BLKSIZ];
};

void md4_init(struct md4_ctx *);
void md4_update(struct md4_ctx *, uint8_t *, size_t);
void md4_final(uint8_t *, struct md4_ctx *);
