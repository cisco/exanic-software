#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <assert.h>
#include <sched.h>
#include <malloc.h>
#include <string.h>
#include "../rwlock.h"
#include "../lock.h"
#include "../structs.h"
#include "../latency.h"


#define MAX_EXASOCK_LATENCY_STREAMS  (20)
#define NUM_LATENCY_SAMPLES_PER_STREAM (10000)
#define NUM_PERCENTILES 11

struct latency_tag
{
    const char* start_function;
    const char* end_function;
    int start_line;
    int end_line;
};

struct latency_stream
{
    struct latency_tag tag;
    int index;
    int count;
    uint64_t samples[NUM_LATENCY_SAMPLES_PER_STREAM];    
};

struct latency_data
{
    struct latency_stream streams [MAX_EXASOCK_LATENCY_STREAMS];
    int num_streams;
};


static struct latency_data* lat = NULL;

uint64_t rdtsc(void)
{
    uint32_t hi, lo;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)lo | ((uint64_t)hi << 32));
}

bool compare_tag(struct latency_tag* t1, struct latency_tag* t2)
{
    if(!strcmp(t1->start_function, t2->start_function) && 
       !strcmp(t1->end_function, t2->end_function) &&
        t1->start_line == t2->start_line &&
        t1->end_line == t2->end_line)
        return true;
    else
        return false;
}

struct latency_stream* search_stream(struct latency_tag* t)
{
    struct latency_stream* stream;
    int i = 0;
    for (i = 0; i < lat->num_streams; i++)
    {
        stream = &lat->streams[i];
        if (compare_tag(t, &stream->tag))
            return stream;
    }
    return NULL;
}

struct latency_stream* alloc_stream(struct latency_tag* t)
{
    struct latency_stream* s;
    if (lat->num_streams == MAX_EXASOCK_LATENCY_STREAMS)
        return NULL;

    s = &lat->streams[lat->num_streams++];
    s->tag.start_function = t->start_function;
    s->tag.end_function = t->end_function;
    s->tag.start_line = t->start_line;
    s->tag.end_line = t->end_line;
    return s;
}

void add_sample_to_stream(struct latency_stream* s, uint64_t sample)
{
    s->samples[s->index++] = sample;
    s->count++;
    if (s->index == NUM_LATENCY_SAMPLES_PER_STREAM)
        s->index = 0;
}

void add_latency_sample(struct latency_tag* t, uint64_t sample)
{
    struct latency_stream* s;
    s = search_stream(t);
    if (s == NULL)
    {
        /* if there is no existing stream for this tag
           allocate a new stream */
        s = alloc_stream(t);
        if (s == NULL)
            return;
    }
    /* add new sample to the stream */
    add_sample_to_stream(s, sample);
}

void latency_measure(const char* function_name, int line, bool start, int index)
{
    uint64_t latency_sample;
    static uint64_t start_ts[MAX_EXASOCK_LATENCY_STREAMS];
    static const char* start_func_name[MAX_EXASOCK_LATENCY_STREAMS];
    static int start_line_number[MAX_EXASOCK_LATENCY_STREAMS];

    if (lat == NULL)
        lat = (struct latency_data*) calloc(1, sizeof(struct latency_data));

    if (index >= MAX_EXASOCK_LATENCY_STREAMS)
        return;

    if (start)
    {
        start_ts[index] = rdtsc();
        start_func_name[index] = function_name;
        start_line_number[index] = line;
        return;
    }
    else
    {
        struct latency_tag t;
        t.start_function = start_func_name[index];
        t.end_function = function_name;
        t.start_line = start_line_number[index];
        t.end_line = line;
        latency_sample = rdtsc() - start_ts[index];
        //printf("tag: %s(%d)  - %s(%d), latency = %lu\n", t.start_function, t.start_line, 
        //       t.end_function, t.end_line, latency_sample);
        add_latency_sample(&t, latency_sample);
    }
}

__attribute__((visibility("default")))
void clear_latencies(void)
{
    memset(lat, 0, sizeof(struct latency_data));
    lat->num_streams = 0;
}

int compare_uint64_val(const void* left, const void* right)
{
    uint64_t l = *(uint64_t*)left;
    uint64_t r = *(uint64_t*)right;
    return l - r;
}

double measure_cpu_clock(double* cpu_clock_freq_ghz)
{
    struct timeval t1, t2;
    uint64_t start_ts, end_ts;
    double us;
        double mhz_freq;
    double clock_period;

    /* get times and tsc vlaue before the usleep and after
        */
    gettimeofday(&t1, NULL);
    start_ts = rdtsc();
    usleep(1000);
    gettimeofday(&t2, NULL);
    end_ts = rdtsc();

    /* find how many microseconds passed between 2 gettimeofday calls */
    us = ((t2.tv_sec - t1.tv_sec) * 1000000) - (t1.tv_usec - t2.tv_usec);
    /* divide number of cycles by the us value and get the mhz freq */
    mhz_freq = (end_ts - start_ts) / us ;
    *cpu_clock_freq_ghz = mhz_freq * 0.001;
    clock_period = 1.0 / *cpu_clock_freq_ghz;
    printf("cpu freq = %f\n", *cpu_clock_freq_ghz);
    printf("cpu clock period = %f ns\n", clock_period);

    return clock_period;
}


double ghz;
void calibrate_tsc()
{
    struct timeval start_tv, stop_tv;
    uint64_t start_tsc, stop_tsc;
    long usec;
    volatile int i;

    gettimeofday(&start_tv, NULL);
    start_tsc = rdtsc();

    for (i = 0; i < 10000000; i++);

    gettimeofday(&stop_tv, NULL);
    stop_tsc = rdtsc();


    usec = (stop_tv.tv_sec - start_tv.tv_sec) * 1000000
        + stop_tv.tv_usec - start_tv.tv_usec;

    ghz = 0.001 * (stop_tsc - start_tsc) / usec;

    printf("%f\n", ghz);
}

void print_single_latency_stream(struct latency_stream* s, double cpu_clock_period, double ghz)
{
    double percentiles[] = {99.999, 99, 95, 90, 75, 50, 25, 10, 5, 1, 0};
    double min_ns = -1;
    double max_ns = -1;
    int j = 0;
    int c;
    printf("latency values between %s[%d] - %s[%d]\n", s->tag.start_function, s->tag.start_line,
            s->tag.end_function, s->tag.end_line);

#ifdef PRINT_COLLECTED_SAMPLES
    {
        int most_early_index = 0;
        if (s->count >= NUM_LATENCY_SAMPLES_PER_STREAM)
            most_early_index = s->index;
        else
            most_early_index = 0;

        c = s->count % NUM_LATENCY_SAMPLES_PER_STREAM;
        for (j = most_early_index; c != 0; j++, c--)
        {
            int idx = j % NUM_LATENCY_SAMPLES_PER_STREAM;
            uint64_t sample = s->samples[idx];
            printf("\t [%d] %lu\n", idx, sample);
        }
    }
#endif /* ifdef PRINT_COLLECTED_SAMPLES */

    /* printing percentiles */
    c = (s->count > NUM_LATENCY_SAMPLES_PER_STREAM) ? (NUM_LATENCY_SAMPLES_PER_STREAM) : (s->count);
    qsort(s->samples, c, sizeof(uint64_t), compare_uint64_val);

    min_ns = s->samples[0] * cpu_clock_period;
    max_ns = s->samples[c - 1] * cpu_clock_period;
    printf(" - min latency = %.2f ns, %lu cycles\n", min_ns, s->samples[0]);
    printf(" - max latency = %.2f ns, %lu cycles\n", max_ns, s->samples[c - 1]);
    printf(" - dispersion: %.2f ns\n", max_ns - min_ns);

#ifdef PRINT_SORTED_SAMPLES
    for (j = 0; c != 0; j++, c--)
        printf("\t [%d] %lu\n", j, s->samples[j]);
#endif /* PRINT_SORTED_SAMPLES */
    
    c = (s->count > NUM_LATENCY_SAMPLES_PER_STREAM) ? (NUM_LATENCY_SAMPLES_PER_STREAM) : (s->count);
    for (j = 0; j < sizeof(percentiles) / sizeof(double); j++)
    {
        int p = (percentiles[j] / 100.0) * c;
        double ns =  s->samples[p] * cpu_clock_period;
        printf(" - percentile [%2.2f] = %.2f ns, %lu cycles\n", percentiles[j], ns, s->samples[p]);
    }
    printf("\n");
}

__attribute__((visibility("default")))
void print_exasock_latencies(void)
{
    int i = 0;
    double cpu_clock_period = 0;
    double ghz = 0;

    cpu_clock_period = measure_cpu_clock(&ghz);


    if (lat == NULL)
    {
        printf("no latency streams found\n");
        return;
    }

    printf("found %d latency streams\n", lat->num_streams);
    for (i = 0; i < lat->num_streams; i++)
        print_single_latency_stream(&lat->streams[i], cpu_clock_period, ghz);
}