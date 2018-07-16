#ifndef EXASOCK_SIPHASH_H
#define EXASOCK_SIPHASH_H

/*
 * siphash implementation from Linux 4.18 for use when compiling against
 * kernel versions before 4.11
 */

typedef struct {
    uint64_t key[2];
} siphash_key_t;

/* provide own implementation here for compatibility */
static inline uint64_t
exasock_rol64(uint64_t word, unsigned int shift)
{
    return (word << shift) | (word >> (64 - shift));
}

#define SIPROUND \
	do { \
	v0 += v1; v1 = exasock_rol64(v1, 13); \
    v1 ^= v0; v0 = exasock_rol64(v0, 32); \
	v2 += v3; v3 = exasock_rol64(v3, 16); v3 ^= v2; \
	v0 += v3; v3 = exasock_rol64(v3, 21); v3 ^= v0; \
	v2 += v1; v1 = exasock_rol64(v1, 17); \
    v1 ^= v2; v2 = exasock_rol64(v2, 32); \
	} while (0)

#define PREAMBLE(len) \
	u64 v0 = 0x736f6d6570736575ULL; \
	u64 v1 = 0x646f72616e646f6dULL; \
	u64 v2 = 0x6c7967656e657261ULL; \
	u64 v3 = 0x7465646279746573ULL; \
	u64 b = ((u64)(len)) << 56; \
	v3 ^= key->key[1]; \
	v2 ^= key->key[0]; \
	v1 ^= key->key[1]; \
	v0 ^= key->key[0];

#define POSTAMBLE \
	v3 ^= b; \
	SIPROUND; \
	SIPROUND; \
	v0 ^= b; \
	v2 ^= 0xff; \
	SIPROUND; \
	SIPROUND; \
	SIPROUND; \
	SIPROUND; \
	return (v0 ^ v1) ^ (v2 ^ v3);

static inline uint64_t
siphash_3u32(const uint32_t first, const uint32_t second,
             const uint32_t third, const siphash_key_t *key)
{
    uint64_t combined = (uint64_t)second << 32 | first;
	PREAMBLE(12)
	v3 ^= combined;
	SIPROUND;
	SIPROUND;
	v0 ^= combined;
	b |= third;
	POSTAMBLE
}

#endif /* EXASOCK_SIPHASH_H */
