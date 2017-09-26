#include "exanic.h"
#include "pcie_if.h"
#include "ioctl.h"
#include "time.h"

#define NANOS_PER_SEC (1000ULL * 1000 * 1000)
#define PICOS_PER_SEC (1000ULL * 1000 * 1000 * 1000)

/* Read 64 bit hardware time, correcting for rollover.
 * Note that exanic_cycles_t is a signed 64 bit value and, for the
 * 4Ghz counter on the ExaNIC HPT variant, will overflow in 2043.
 * After that we'll need to move to 128 bit integers or find another
 * solution.
 * */
static exanic_cycles_t exanic_read_hw_time_64(struct exanic *exanic)
{
    uint32_t hi1, hi2, lo;

    hi1 = exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_HW_TIME_HI)];
    lo = exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_HW_TIME)];
    hi2 = exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_HW_TIME_HI)];

    if (hi1 == hi2)
        return ((int64_t)hi1) << 32 | lo;
    else if (lo < 0x80000000)
        return ((int64_t)hi2) << 32 | lo;
    else
        return ((int64_t)hi1) << 32 | lo;
}

exanic_cycles_t exanic_expand_timestamp(exanic_t *exanic, exanic_cycles32_t timestamp)
{
    exanic_cycles_t time_tick;

    if (exanic->tick_hz == 0)
        return 0;

    /* Get the approximate current hardware time in ExaNIC clock ticks */
    if ((exanic->caps & EXANIC_CAP_HW_TIME_HI) &&
            (exanic->info_page == NULL || exanic->info_page->hw_time == 0))
        time_tick = exanic_read_hw_time_64(exanic);
    else
        time_tick = exanic->info_page->hw_time;

    /* Round to nearest ExaNIC clock tick value that matches the timestamp */
    time_tick += (int32_t)(timestamp - time_tick);

    return time_tick;
}

void exanic_cycles_to_timespecps(exanic_t *exanic, exanic_cycles_t cycles,
        struct exanic_timespecps *tsps)
{
    tsps->tv_sec  = cycles / exanic->tick_hz;

    /* This complicated bit of maths is necessary to avoid overflows while
     * maintaining precision in the conversion between cycles and picoseconds */
    uint64_t frac_cycles = cycles % exanic->tick_hz;
    tsps->tv_psec = (frac_cycles * (PICOS_PER_SEC / exanic->tick_hz)) +
            (frac_cycles * (PICOS_PER_SEC % exanic->tick_hz) / exanic->tick_hz);

}

void exanic_cycles_to_timespec(exanic_t *exanic, exanic_cycles_t cycles,
        struct timespec *ts)
{
    ts->tv_sec  = cycles / exanic->tick_hz;
    ts->tv_nsec = (cycles % exanic->tick_hz) * NANOS_PER_SEC /
              exanic->tick_hz;
}

int64_t exanic_cycles_to_ns(exanic_t *exanic, exanic_cycles_t cycles)
{
    struct timespec ts;
    exanic_cycles_to_timespec(exanic, cycles, &ts);
    return ts.tv_sec * NANOS_PER_SEC + ts.tv_nsec;
}

int64_t exanic_cycles_to_ps(exanic_t *exanic, exanic_cycles_t cycles,
        bool *overflow)
{
    struct exanic_timespecps tsps;
    exanic_cycles_to_timespecps(exanic, cycles, &tsps);
    if (overflow)
        *overflow = (tsps.tv_sec >= INT64_MAX / exanic->tick_hz);
    return tsps.tv_sec * PICOS_PER_SEC + tsps.tv_psec;
}


/* Deprecated! */ 
uint64_t exanic_timestamp_to_counter(exanic_t *exanic, uint32_t timestamp)
{
    const uint64_t timestamp_expanded =
            exanic_expand_timestamp(exanic, timestamp);
    struct timespec ts;
    exanic_cycles_to_timespec(exanic, timestamp_expanded, &ts);
    return ts.tv_sec * NANOS_PER_SEC + ts.tv_nsec;
}

/* Deprecated! */ 
uint32_t exanic_counter_to_timestamp(exanic_t *exanic, uint64_t counter)
{
    return counter / NANOS_PER_SEC * exanic->tick_hz +
            (counter % NANOS_PER_SEC) * exanic->tick_hz / NANOS_PER_SEC;
}
