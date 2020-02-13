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

#define TRY(x)                                                          \
    do {                                                                \
        int __rc = (x);                                                 \
        if ( __rc < 0 ) {                                               \
            fprintf(stderr, "ERROR: TRY(%s) failed\n", #x);             \
            fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);   \
            fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",             \
                    __rc, errno, strerror(errno));                      \
            abort();                                                    \
        }                                                               \
    } while( 0 )

#define TEST(x)                                                         \
    do {                                                                \
        if( ! (x) ) {                                                   \
            fprintf(stderr, "ERROR: TEST(%s) failed\n", #x);            \
            fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);   \
            abort();                                                    \
        }                                                               \
    } while( 0 )

#define EXA_TRY(x)                                                      \
    do {                                                                \
        if (!(x)) {                                                     \
            fprintf(stderr, "ERROR: EXA_TRY(%s) failed\n", #x);         \
            fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);   \
            fprintf(stderr, "%s\n", exanic_get_last_error());           \
            abort();                                                    \
        }                                                               \
    } while( 0 )                                                        \

#ifdef __cplusplus
extern "C" {
#endif
void timing_print(timing_t *stats, int count, int raw_counts);
void init_packet(char *data, int data_size);
#ifdef __cplusplus
}
#endif

