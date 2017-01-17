#define NSTATE 624

struct mt {
	uint32_t state[NSTATE];
	size_t i;
};
