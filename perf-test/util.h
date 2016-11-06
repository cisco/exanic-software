#include <stdint.h>

typedef uint64_t timing_t;

/* use rdtscp rather than rdtsc as rdtscp is serializing */
#define rdtscll(val) do { \
     unsigned int __a,__d,__c; \
     asm volatile("rdtscp" : "=a" (__a), "=d" (__d), "=c" (__c)); \
     (val) = ((unsigned long)__a) | (((unsigned long)__d)<<32); \
} while(0)

#define timing_start rdtscll
#define timing_end rdtscll

#ifdef __cplusplus
extern "C" {
#endif
void timing_print(timing_t *stats, int count, int raw_counts);
void init_packet(char *data, int data_size);
#ifdef __cplusplus
}
#endif

