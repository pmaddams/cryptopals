#include <sys/types.h>

#define NSTATES 624

struct mt {
	uint32_t state[NSTATES];
	size_t i;
};

void mt_init(struct mt *, uint32_t);
uint32_t mt_rand(struct mt *);
