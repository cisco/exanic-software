#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "util.h"

#define CALIBRATION_TIME 1000 /* us */

float get_cpu_ghz()
{
    unsigned int eax, ebx, ecx, edx;
    uint64_t ts_start_us, ts_end_us, ts_temp_us, time_us, start_cycles, end_cycles;
    struct timeval ts;
    int has_invariant_tsc;
    float cpu_frequency_ghz;

    asm("cpuid" : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (0x80000007));
    has_invariant_tsc = edx & (1 << 8);
    if (!has_invariant_tsc)
    {
        fprintf(stderr, "WARNING: Cannot produce reliable results on machines without an invariant Time Stamp Counter\n");
    }

    while (1)
    {
        gettimeofday(&ts, NULL);
        ts_temp_us = (ts.tv_usec + ts.tv_sec * 1000000);

        /* wait for microsecond to tick over to improve accuracy */
        do
        {
            gettimeofday(&ts, NULL);
            timing_start(start_cycles);
            ts_start_us = (ts.tv_usec + ts.tv_sec * 1000000);
        } while (ts_start_us == ts_temp_us);

        /* protect against context switch between gettimeofday
         * and timing_start by rechecking gettimeofday */
        gettimeofday(&ts, NULL);
        ts_temp_us = (ts.tv_usec + ts.tv_sec * 1000000);
        if (ts_temp_us != ts_start_us)
            continue;

        break;
    }

    while (1)
    {
        gettimeofday(&ts, NULL);
        timing_end(end_cycles);
        ts_end_us = (ts.tv_usec + ts.tv_sec * 1000000);
        time_us = ts_end_us - ts_start_us;
        if (time_us < CALIBRATION_TIME)
            continue;

        /* protect against context switch between gettimeofday
         * and timing_end by rechecking gettimeofday */
        gettimeofday(&ts, NULL);
        ts_end_us = (ts.tv_usec + ts.tv_sec * 1000000);
        if (ts_end_us - ts_start_us > time_us)
            continue;

        break;
    }

    cpu_frequency_ghz = (float)(end_cycles - start_cycles) / (1000*time_us);
    return cpu_frequency_ghz;
}

static unsigned long to_ns(float cpu_ghz, timing_t value)
{
    return (unsigned long)((float)value / cpu_ghz);
}

static int compare_uint64(const void *pa, const void *pb)
{
    uint64_t a = *(const uint64_t *)pa;
    uint64_t b = *(const uint64_t *)pb;
    return (a < b) ? -1 : (a > b) ? +1 : 0;
}

void timing_print(timing_t *stats, int count, int raw_counts)
{
    int i;
    if (raw_counts)
        for (i = 0; i < count; i++)
            printf("%llu\n", (unsigned long long)stats[i]);
    else
    {
        float cpu_ghz = get_cpu_ghz();

        qsort(stats, count, sizeof(timing_t), compare_uint64);

        float percentiles[12] = { 0, 1, 5, 10, 25, 50, 75, 90, 95, 99, 99.999, 100 };

        printf("CPU GHz = %.2f\n", cpu_ghz);

        for (i = 0; i < sizeof(percentiles) / sizeof(float); i++)
        {
            int ordinal_rank = (int) (percentiles[i] / 100 * (count - 1));
            printf("Percentile %.3f = %luns\n", percentiles[i], to_ns(cpu_ghz, stats[ordinal_rank]));
        }

        if (count < 1000)
            printf("Warning: Percentile breakdown may be inaccurate for < 1000 samples.\n");
    }
}

void init_packet(char *data, int data_size)
{
    int i;
    for (i = 0; i < data_size; i++)
        data[i] = i;
    if (data_size < 6)
    {
        fprintf(stderr, "packet too short\n");
        return;
    }
    /* dest addr = broadcast */
    memset(data, 0xff, 6);
}
