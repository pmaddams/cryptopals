#include <sys/types.h>

#define NSTATES	624
#define BLKSIZ	4

struct mt {
	uint32_t state[NSTATES];
	size_t i;
};

void mt_init(struct mt *, uint32_t);
uint32_t mt_rand(struct mt *);
uint8_t *mt_crypt(uint8_t *, size_t, uint16_t);
