#include <sys/types.h>

#define NSTATE 624

struct mt {
	uint32_t state[NSTATE];
	size_t i;
};

void mt_init(struct mt *, uint32_t);
uint32_t mt_rand(struct mt *);
