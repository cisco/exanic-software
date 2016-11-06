#include <sys/time.h>

#include "exanic.h"
#include "pcie_if.h"
#include "ioctl.h"

/* Read 64 bit hardware time, correcting for rollover */
static uint64_t exanic_read_hw_time_64(struct exanic *exanic)
{
    uint32_t hi1, hi2, lo;

    hi1 = exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_HW_TIME_HI)];
    lo = exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_HW_TIME)];
    hi2 = exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_HW_TIME_HI)];

    if (hi1 == hi2)
        return ((uint64_t)hi1) << 32 | lo;
    else if (lo < 0x80000000)
        return ((uint64_t)hi2) << 32 | lo;
    else
        return ((uint64_t)hi1) << 32 | lo;
}

uint64_t exanic_timestamp_to_counter(exanic_t *exanic, uint32_t timestamp)
{
    uint64_t time_tick;

    if (exanic->tick_hz == 0)
        return 0;

    /* Get the approximate current hardware time in ExaNIC clock ticks */
    if (exanic->caps & EXANIC_CAP_HW_TIME_HI)
        time_tick = exanic_read_hw_time_64(exanic);
    else
        time_tick = exanic->info_page->hw_time;

    /* Round to nearest ExaNIC clock tick value that matches the timestamp */
    time_tick += (int32_t)(timestamp - time_tick);

    /* Convert to nanoseconds since epoch */
    return time_tick / exanic->tick_hz * 1000000000 +
        (time_tick % exanic->tick_hz) * 1000000000 / exanic->tick_hz;
}

uint32_t exanic_counter_to_timestamp(exanic_t *exanic, uint64_t counter)
{
    return counter / 1000000000 * exanic->tick_hz +
        (counter % 1000000000) * exanic->tick_hz / 1000000000;
}
