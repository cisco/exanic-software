#define _GNU_SOURCE
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/timex.h>

#if HAVE_PTP_CLOCK_H
#include <linux/ptp_clock.h>
#else
#include "../ptp_clock_compat.h"
#endif

#include <exanic/exanic.h>
#include <exanic/config.h>
#include <exanic/pcie_if.h>
#include <exanic/register.h>
#include <exanic/util.h>

#include "common.h"

#define SYSLOG_ID "exanic-clock-sync"
#define EXANIC_MAX 16

#define CLOCKFD 3
#define FD_TO_CLOCKID(fd) ((~(clockid_t)(fd) << 3) | CLOCKFD)


/* clock_adjtime is not available in older versions of glibc */
#if !__GLIBC_PREREQ(2, 14)
#include <sys/syscall.h>
#if !defined(__NR_clock_adjtime) && defined(__amd64__)
#define __NR_clock_adjtime 305
#elif !defined(__NR_clock_adjtime) && defined(__i386__)
#define __NR_clock_adjtime 343
#endif
static int clock_adjtime(clockid_t id, struct timex *tx)
{
    return syscall(__NR_clock_adjtime, id, tx);
}
#endif


void reset_drift(struct drift *d)
{
    d->n = 0;
    d->startup = 1;
}


int calc_drift(struct drift *d, double *val)
{
    double drift;
    int i;

    if (d->startup)
    {
        drift = 0;
        for (i = 0; i < d->n; i++)
            drift += d->drift[i];
        if (d->n > 0)
            drift /= d->n;
    }
    else
    {
        drift = 0;
        for (i = 0; i < DRIFT_LEN; i++)
            drift += d->drift[i];
        drift /= DRIFT_LEN;
    }

    *val = drift;

    /* Return nonzero if there is at least one measurement */
    return !d->startup || d->n > 0;
}


void record_drift(struct drift *d, double val)
{
    d->drift[d->n] = val;
    if (++d->n >= DRIFT_LEN)
        d->n = d->startup = 0;
}


int get_clock_adj(int clkfd, double *adj)
{
    struct timex tx;

    memset(&tx, 0, sizeof(tx));
    if (clock_adjtime(FD_TO_CLOCKID(clkfd), &tx) == -1)
        return -1;

    /* freq is in units of ppm with a 16 bit fractional part */
    *adj = tx.freq / 65536000000.0;
    return 0;
}


int set_clock_adj(int clkfd, double adj)
{
    struct timex tx;

    memset(&tx, 0, sizeof(tx));
    tx.modes = ADJ_FREQUENCY;
    tx.freq = adj * 65536000000.0;

    return clock_adjtime(FD_TO_CLOCKID(clkfd), &tx);
}


int get_clock_time(int clkfd, uint64_t *time_ns)
{
    struct timespec ts;

    if (clock_gettime(FD_TO_CLOCKID(clkfd), &ts) == -1)
        return -1;

    *time_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    return 0;
}


int set_clock_time(int clkfd, uint64_t time_ns)
{
    struct timespec ts;

    ts.tv_sec = time_ns / 1000000000;
    ts.tv_nsec = time_ns % 1000000000;

    return clock_settime(FD_TO_CLOCKID(clkfd), &ts);
}


int get_tai_offset(int *offset)
{
    struct timex tx;

    memset(&tx, 0, sizeof(tx));
    if (adjtimex(&tx) == -1)
        return -1;

    *offset = tx.tai;
    return 0;
}


int set_tai_offset(int offset)
{
    struct timex tx;

    memset(&tx, 0, sizeof(tx));
    tx.modes = ADJ_TAI;
    tx.constant = offset;

    return adjtimex(&tx);
}


/* Determine how the hardware clock is externally synchronized */
enum phc_source get_phc_source(int clkfd, exanic_t *exanic)
{
    if (exanic != NULL && exanic_get_hw_type(exanic) == EXANIC_HW_X10_GM)
    {
        uint32_t conf0;

        conf0 = exanic_register_read(exanic, REG_PTP_INDEX(REG_PTP_CONF0));

        if ((conf0 & EXANIC_PTP_CONF0_GPS_CLOCK_SYNC) != 0)
            return PHC_SOURCE_EXANIC_GPS;
    }

    /* TODO: Check for ptp4l */

    return PHC_SOURCE_NONE;
}


/* Return 0 if hardware time is good, -1 otherwise
 * This assumes ExaNIC GPS is available and enabled */
int check_exanic_gps_time(exanic_t *exanic)
{
    uint32_t gps_status;

    gps_status = exanic_register_read(exanic,
            REG_PTP_INDEX(REG_PTP_GPS_STATUS));

    /* TIME_OK bit is set when the clock is synchronized to GPS time */
    if ((gps_status & EXANIC_PTP_GPS_STATUS_TIME_OK) != 0)
        return 0;

    return -1;
}


/* This assumes ExaNIC GPS is available and enabled and hardware time is good */
int get_exanic_gps_tai_offset(exanic_t *exanic, int *offset)
{
    int32_t reg;

    reg = exanic_register_read(exanic, REG_PTP_INDEX(REG_PTP_TAI_OFFSET));

    *offset = reg;
    return 0;
}
