#include <endian.h>
#include <string.h>

#include "md4.h"

#define C1		0x5a827999
#define C2		0x6ed9eba1

#define F1(b, c, d)	(d ^ (b & (c ^ d)))
#define F2(b, c, d)	((b & c) | (b & d) | (c & d))
#define F3(b, c, d)	(b ^ c ^ d)

#define STEP(f, a, b, c, d, in, shift)			\
	do {						\
		a += f(b, c, d) + in;			\
		a = a << shift | a >> (32-shift);	\
	} while (0)

void
md4_init(struct ctx *ctx)
{
	ctx->count = 0;

	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

static void
md4_transform(uint32_t *state, uint8_t *blk)
{
	uint32_t a, b, c, d, in[BLKSIZ/4];

	for (a = 0; a < BLKSIZ/4; a++)
		in[a] = htole32(((uint32_t *) blk)[a]);

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	STEP(F1, a, b, c, d, in[0],	3);
	STEP(F1, d, a, b, c, in[1],	7);
	STEP(F1, c, d, a, b, in[2],	11);
	STEP(F1, b, c, d, a, in[3],	19);
	STEP(F1, a, b, c, d, in[4],	3);
	STEP(F1, d, a, b, c, in[5],	7);
	STEP(F1, c, d, a, b, in[6],	11);
	STEP(F1, b, c, d, a, in[7],	19);
	STEP(F1, a, b, c, d, in[8],	3);
	STEP(F1, d, a, b, c, in[9],	7);
	STEP(F1, c, d, a, b, in[10],	11);
	STEP(F1, b, c, d, a, in[11],	19);
	STEP(F1, a, b, c, d, in[12],	3);
	STEP(F1, d, a, b, c, in[13],	7);
	STEP(F1, c, d, a, b, in[14],	11);
	STEP(F1, b, c, d, a, in[15],	19);

	STEP(F2, a, b, c, d, C1+in[0],	3);
	STEP(F2, d, a, b, c, C1+in[4],	5);
	STEP(F2, c, d, a, b, C1+in[8],	9);
	STEP(F2, b, c, d, a, C1+in[12],	13);
	STEP(F2, a, b, c, d, C1+in[1],	3);
	STEP(F2, d, a, b, c, C1+in[5],	5);
	STEP(F2, c, d, a, b, C1+in[9],	9);
	STEP(F2, b, c, d, a, C1+in[13],	13);
	STEP(F2, a, b, c, d, C1+in[2],	3);
	STEP(F2, d, a, b, c, C1+in[6],	5);
	STEP(F2, c, d, a, b, C1+in[10],	9);
	STEP(F2, b, c, d, a, C1+in[14],	13);
	STEP(F2, a, b, c, d, C1+in[3],	3);
	STEP(F2, d, a, b, c, C1+in[7],	5);
	STEP(F2, c, d, a, b, C1+in[11],	9);
	STEP(F2, b, c, d, a, C1+in[15],	13);

	STEP(F3, a, b, c, d, C2+in[0],	3);
	STEP(F3, d, a, b, c, C2+in[8],	9);
	STEP(F3, c, d, a, b, C2+in[4],	11);
	STEP(F3, b, c, d, a, C2+in[12],	15);
	STEP(F3, a, b, c, d, C2+in[2],	3);
	STEP(F3, d, a, b, c, C2+in[10],	9);
	STEP(F3, c, d, a, b, C2+in[6],	11);
	STEP(F3, b, c, d, a, C2+in[14],	15);
	STEP(F3, a, b, c, d, C2+in[1],	3);
	STEP(F3, d, a, b, c, C2+in[9],	9);
	STEP(F3, c, d, a, b, C2+in[5],	11);
	STEP(F3, b, c, d, a, C2+in[13],	15);
	STEP(F3, a, b, c, d, C2+in[3],	3);
	STEP(F3, d, a, b, c, C2+in[11],	9);
	STEP(F3, c, d, a, b, C2+in[7],	11);
	STEP(F3, b, c, d, a, C2+in[15],	15);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}

void
md4_update(struct ctx *ctx, uint8_t *buf, size_t len)
{
	size_t have, need;

	have = (size_t) ((ctx->count >> 3) & (BLKSIZ-1));
	need = BLKSIZ - have;

	ctx->count += (uint64_t) len << 3;

	if (len >= need) {
		if (have > 0) {
			memcpy(ctx->buf+have, buf, need);
			md4_transform(ctx->state, ctx->buf);
			buf += need;
			len -= need;
			have = 0;
		}
		while (len >= BLKSIZ) {
			md4_transform(ctx->state, buf);
			buf += BLKSIZ;
			len -= BLKSIZ;
		}
	}

	if (len > 0)
		memcpy(ctx->buf+have, buf, len);
}

static void
md4_pad(struct ctx *ctx)
{
	uint8_t count[8];
	size_t padlen;

	padlen = BLKSIZ - ((ctx->count>>3) & (BLKSIZ-1));
	*((uint64_t *) count) = le64toh(ctx->count);

	if (padlen < 1 + 8)
		padlen += BLKSIZ;

	md4_update(ctx, "\x80", 1);

	while (--padlen > 8)
		md4_update(ctx, "\x00", 1);

	md4_update(ctx, count, 8);
}

void
md4_final(uint8_t *buf, struct ctx *ctx)
{
	size_t i;

	md4_pad(ctx);

	for (i = 0; i < NSTATE; i++)
		((uint32_t *) buf)[i] = le32toh(ctx->state[i]);
}
