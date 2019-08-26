#define _GNU_SOURCE
#include <time.h>
#include <math.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
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

#ifndef ADJ_SETOFFSET
#define ADJ_SETOFFSET 0x0100
#endif

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
    int i;

    d->n = 0;
    for (i = 0; i < DRIFT_LEN; i++)
        d->drift[i] = d->weight[i] = 0;
}


/* weighted average of the drift history */
int calc_drift(struct drift *d, double *val)
{
    double drift, weight;
    int i;

    drift = weight = 0;
    for (i = 0; i < DRIFT_LEN; i++)
    {
        drift += d->drift[i] * d->weight[i];
        weight += d->weight[i];
    }

    if (weight > 0)
    {
        *val = drift / weight;
        return 1;
    }
    else
        return 0;
}


void record_drift(struct drift *d, double val, double weight)
{
    d->drift[d->n] = val;
    d->weight[d->n] = weight;
    if (++d->n >= DRIFT_LEN)
        d->n = 0;
}


void reset_error(struct error *e)
{
    e->n = 0;
    e->startup = 1;
}


static int cmp_double(const void *a, const void *b)
{
    double d = *(double *)a - *(double *)b;
    return d < 0 ? -1 : d > 0 ? 1 : 0;
}


/* median of the error history */
int calc_error(struct error *e, double *val)
{
    double error[ERROR_LEN];
    int i, c;

    if (e->startup)
        c = e->n;
    else
        c = ERROR_LEN;

    if (c == 0)
        return 0;

    for (i = 0; i < c; i++)
        error[i] = e->error[i];
    qsort(error, c, sizeof(double), cmp_double);

    if ((c % 2) == 0)
        *val = (error[c / 2 - 1] + error[c / 2]) / 2;
    else
        *val = error[c / 2];

    return 1;
}


void record_error(struct error *e, double correction, double val)
{
    int i, c;

    if (e->startup)
        c = e->n;
    else
        c = ERROR_LEN;

    for (i = 0; i < c; i++)
        e->error[i] += correction;

    e->error[e->n] = val;
    if (++e->n >= ERROR_LEN)
        e->n = e->startup = 0;
}


void reset_rate_error(struct rate_error *r, double interval)
{
    int i;

    r->partial = 0;
    r->n = 0;
    r->startup = 1;
    r->interval = interval;
    for (i = 0; i < RATE_ERROR_LEN; ++i)
        r->error[i] = 0;
}


int calc_rate_error(struct rate_error *r, double *err)
{
    if (r->n == 0 && r->startup)
    {
        if (r->partial == 0)
            return 0;
        *err = r->error[0] / r->partial;
        return 1;
    }
    else
    {
        int n = (r->n == 0) ? RATE_ERROR_LEN - 1 : r->n - 1;
        *err = r->error[n] / r->interval;
        return 1;
    }
}


int calc_rate_error_adev(struct rate_error *r, double *adev)
{
    int i, n, m, samples;
    double err, last_err, avar;

    n = r->n;

    if (r->startup)
        m = 0;
    else
        m = (r->n + 1) % RATE_ERROR_LEN;

    avar = 0;
    samples = 0;
    last_err = 0;
    for (i = m; i != n; i = (i + 1) % RATE_ERROR_LEN)
    {
        err = r->error[i] / r->interval;
        if (i != m)
        {
            avar += (err - last_err) * (err - last_err);
            samples++;
        }
        last_err = err;
    }

    if (samples == 0)
        return 0;

    *adev = sqrt(avar / samples / 2);
    return 1;
}


void record_rate_error(struct rate_error *r, double err, double interval)
{
    while (r->interval - r->partial < interval)
    {
        double rem = r->interval - r->partial;

        r->error[r->n] += err * rem / interval;

        err -= err * rem / interval;
        interval -= rem;

        if (++r->n >= RATE_ERROR_LEN)
            r->n = r->startup = 0;
        r->error[r->n] = 0;
        r->partial = 0;
    }

    r->error[r->n] += err;
    r->partial += interval;
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

    if (!(LONG_MIN / 65536000000.0 < adj && adj < LONG_MAX / 65536000000.0))
    {
        /* adj is out of range or is NaN */
        errno = ERANGE;
        return -1;
    }

    /* Workaround for Linux bug in clock_adjtime - frequency is converted
     * into a signed 32 bit ppb value but it is not checked for overflow */
    if (!(-2.147483648 < adj && adj < 2.147483647))
    {
        errno = ERANGE;
        return -1;
    }

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


int set_clock_time_offset(int clkfd, long offset_ns)
{
    struct timex tx;

    memset(&tx, 0, sizeof(tx));
    tx.modes = ADJ_SETOFFSET | ADJ_NANO;
    if (offset_ns >= 0)
    {
        tx.time.tv_sec = offset_ns / 1000000000;
        tx.time.tv_usec = offset_ns % 1000000000;
    }
    else
    {
        tx.time.tv_sec = offset_ns / 1000000000 - 1;
        tx.time.tv_usec = offset_ns % 1000000000 + 1000000000;
    }

    return clock_adjtime(FD_TO_CLOCKID(clkfd), &tx);
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


#define PHC_MAX 32
struct phc
{
    dev_t dev;
    enum phc_status status;
};

static struct phc phc[PHC_MAX];
int num_phc = 0;


/* Add the hardware clock to the list of clocks synced by exanic-clock-sync */
void set_phc_synced(int clkfd)
{
    struct stat st;

    if (fstat(clkfd, &st) == 0 && num_phc < PHC_MAX)
    {
        phc[num_phc].dev = st.st_rdev;
        phc[num_phc].status = PHC_STATUS_UNKNOWN;
        num_phc++;
    }
}


/* Determine how the hardware clock is synchronized */
enum phc_source get_phc_source(int clkfd, exanic_t *exanic)
{
    struct stat st;
    int i;

    if (exanic != NULL && exanic->hw_info.flags.gps)
    {
        uint32_t conf0;

        conf0 = exanic_register_read(exanic, REG_PTP_INDEX(REG_PTP_CONF0));

        if ((conf0 & EXANIC_PTP_CONF0_GPS_CLOCK_SYNC) != 0)
            return PHC_SOURCE_EXANIC_GPS;
    }

    if (fstat(clkfd, &st) == 0)
    {
        for (i = 0; i < num_phc; i++)
        {
            if (phc[i].dev == st.st_rdev)
                return PHC_SOURCE_SYNC;
        }
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


/* Store the synchronization status of the given hardware clock */
void update_phc_status(int clkfd, enum phc_status status)
{
    int i;
    struct stat st;

    if (fstat(clkfd, &st) == 0)
    {
        for (i = 0; i < num_phc; i++)
        {
            if (phc[i].dev == st.st_rdev)
            {
                phc[i].status = status;
                return;
            }
        }
    }
}


/* Return the synchronization status as set by update_phc_status() */
enum phc_status get_phc_status(int clkfd)
{
    int i;
    struct stat st;

    if (fstat(clkfd, &st) == 0)
    {
        for (i = 0; i < num_phc; i++)
        {
            if (phc[i].dev == st.st_rdev)
                return phc[i].status;
        }
    }

    return PHC_STATUS_UNKNOWN;
}
