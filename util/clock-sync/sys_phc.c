#include <math.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/ioctl.h>

#if HAVE_PTP_CLOCK_H
#include <linux/ptp_clock.h>
#else
#include "../ptp_clock_compat.h"
#endif

#include <exanic/exanic.h>

#include "common.h"
#include "sys_phc.h"

/* Linux clamps the frequency offset to the range -500ppm to 500ppm */
#define MAX_FREQ_ADJ 0.0005


struct sys_phc_sync_state
{
    char name[16];
    int clkfd;
    exanic_t *exanic;
    enum phc_source phc_source;
    int32_t add_offset_ns; /* Offset to add to system time (ns) */
    int tai_offset;     /* Last known TAI-UTC offset */
    int auto_tai_offset; /* Get TAI offset automatically */
    int tai_offset_wait; /* Nonzero if waiting for valid TAI-UTC offset */
    uint64_t time_ns;   /* Time of last measurement (ns since epoch) */
    uint64_t lat_ns;    /* Measurement latency (ns) */
    double error_ns;    /* Last measured clock error (ns) */
    int invalid;        /* Nonzero if last measurement is not valid */
    double adj;         /* Currently applied adjustment value */
    struct drift drift; /* Estimated drift of the underlying clock */
    struct error error; /* Clock error history */
    int error_mode;     /* Nonzero if there was an error adjusting the clock */
    int log_next;       /* Make sure next measurement is logged */
    int log_reset;      /* Log if clock is reset */
    int init_wait;      /* Nonzero if waiting for source to be synced */
    uint64_t last_log_ns; /* Time of last log message (ns since epoch) */
};


static int ptp_sys_offset(int fd, uint64_t *sys_time_ns,
        uint64_t *hw_time_ns, uint64_t *lat_ns)
{
    struct ptp_sys_offset sysoff;
    uint64_t t1, t2, th;
    uint64_t d = ~0;
    unsigned i;

    memset(&sysoff, 0, sizeof(sysoff));
    sysoff.n_samples = PTP_MAX_SAMPLES;

    if (ioctl(fd, PTP_SYS_OFFSET, &sysoff) == -1)
        return -1;

    *sys_time_ns = *hw_time_ns = 0;

    /* 2n+1 interleaved samples of system time and hardware time
     * Find the 2 consecutive system time readings with the smallest
     * interval and use that as our sample */
    for (i = 0; i < sysoff.n_samples; i++)
    {
        t1 = sysoff.ts[2*i].sec * 1000000000ULL + sysoff.ts[2*i].nsec;
        th = sysoff.ts[2*i+1].sec * 1000000000ULL + sysoff.ts[2*i+1].nsec;
        t2 = sysoff.ts[2*i+2].sec * 1000000000ULL + sysoff.ts[2*i+2].nsec;

        if (d == ~0 || (t2 - t1) < d)
        {
            d = t2 - t1;
            *sys_time_ns = (t1 + t2) / 2;
            *hw_time_ns = th;
        }
    }

    *lat_ns = d;

    return 0;
}


static int get_sys_adj(double *adj)
{
    struct timex tx;

    memset(&tx, 0, sizeof(tx));
    if (adjtimex(&tx) == -1)
        return -1;

    /* freq is in units of ppm with a 16 bit fractional part */
    *adj = tx.freq / 65536000000.0;
    return 0;
}


static int set_sys_adj(double adj)
{
    struct timex tx;

    if (!(-MAX_FREQ_ADJ <= adj && adj <= MAX_FREQ_ADJ))
    {
        /* adj is out of range or is NaN */
        errno = ERANGE;
        return -1;
    }

    memset(&tx, 0, sizeof(tx));
    tx.modes = ADJ_FREQUENCY;
    tx.freq = adj * 65536000000.0;

    return adjtimex(&tx);
}


static int set_sys_time(uint64_t time_ns)
{
    struct timespec ts;

    ts.tv_sec = time_ns / 1000000000;
    ts.tv_nsec = time_ns % 1000000000;

    return clock_settime(CLOCK_REALTIME, &ts);
}


struct sys_phc_sync_state *init_sys_phc_sync(const char *name, int fd,
        exanic_t *exanic, int tai_offset, int auto_tai_offset, int64_t offset)
{
    struct sys_phc_sync_state *state;
    uint64_t sys_time_ns, hw_time_ns, lat_ns;
    int sys_tai_offset;
    double adj;
    enum phc_source phc_source;

    /* First check that the ioctl works */
    if (ptp_sys_offset(fd, &sys_time_ns, &hw_time_ns, &lat_ns) == -1)
    {
        log_printf(LOG_ERR,
                "%s: Error reading time from PTP hardware clock: %s",
                name, strerror(errno));
        return NULL;
    }

    if (get_sys_adj(&adj) == -1)
    {
        log_printf(LOG_ERR, "%s: Error reading current system clock "
                "adjustment: %s", name, strerror(errno));
        return NULL;
    }

    phc_source = get_phc_source(fd, exanic);

    if (phc_source != PHC_SOURCE_EXANIC_GPS && auto_tai_offset)
    {
        log_printf(LOG_ERR, "%s: Unable to get TAI offset, "
                "--tai-offset argument must be provided", name);
        return NULL;
    }

    if (auto_tai_offset)
    {
        /* Get last TAI offset from system */
        if (get_tai_offset(&sys_tai_offset) == -1)
        {
            log_printf(LOG_ERR, "%s: Could not get system TAI offset: %s",
                    name, strerror(errno));
            return NULL;
        }
    }

    state = malloc(sizeof(struct sys_phc_sync_state));

    if (exanic != NULL)
        exanic_retain_handle(exanic);

    snprintf(state->name, sizeof(state->name), "%s", name);
    state->clkfd = fd;
    state->exanic = exanic;
    state->phc_source = phc_source;

    /* Time offset settings */
    state->add_offset_ns = offset;
    state->tai_offset = auto_tai_offset ? sys_tai_offset : tai_offset;
    state->auto_tai_offset = auto_tai_offset;
    state->tai_offset_wait = auto_tai_offset ? 1 : 0;

    log_printf(LOG_INFO, "%s: Starting system clock discipline using "
            "%s clock", state->name, state->name);

    if (state->phc_source == PHC_SOURCE_EXANIC_GPS)
    {
        log_printf(LOG_INFO, "%s: Waiting for GPS sync on %s clock",
                state->name, state->name);
        state->init_wait = 1;
    }
    else if (state->phc_source == PHC_SOURCE_SYNC)
    {
        log_printf(LOG_INFO, "%s: Waiting for sync on %s clock",
                state->name, state->name);
        state->init_wait = 1;
    }
    else
        state->init_wait = 0;

    /* Set up state struct */
    state->invalid = 1;
    state->error_mode = 0;
    state->log_next = 1;
    state->log_reset = 0;
    state->last_log_ns = 0;

    /* Use current adjustment as our initial estimate of drift */
    state->adj = adj;
    reset_drift(&state->drift);
    record_drift(&state->drift, -adj, 1000000000 * POLL_INTERVAL);

    reset_error(&state->error);

    return state;
}


enum sync_status poll_sys_phc_sync(struct sys_phc_sync_state *state)
{
    uint64_t sys_time_ns, hw_time_ns, lat_ns;
    double error_ns, interval_ns, correction_ns, delta_ns, med_error_ns;
    double drift, adj;
    int64_t clock_offset_ns;
    int last_tai_offset;
    int fast_poll = 0;

    /* Check if we are still waiting for hardware clock to be ready */
    if (state->init_wait)
    {
        if (state->phc_source == PHC_SOURCE_EXANIC_GPS)
        {
            /* Waiting for GPS sync on the ExaNIC */
            if (check_exanic_gps_time(state->exanic) == 0)
            {
                log_printf(LOG_INFO, "%s: GPS sync acquired on %s clock",
                        state->name, state->name);
                state->init_wait = 0;
            }
        }
        else if (state->phc_source == PHC_SOURCE_SYNC)
        {
            /* Waiting for source clock to be synced */
            if (get_phc_status(state->clkfd) == PHC_STATUS_SYNCED)
            {
                log_printf(LOG_INFO, "%s: Detected clock sync on %s clock",
                        state->name, state->name);
                state->init_wait = 0;
            }
        }

        /* Hardware clock is not ready */
        if (state->init_wait)
            return SYNC_FAILED;
    }

    if (state->auto_tai_offset)
    {
        last_tai_offset = state->tai_offset;

        /* Get updated TAI offset from time source */
        if (state->phc_source == PHC_SOURCE_EXANIC_GPS)
        {
            if (get_exanic_gps_tai_offset(state->exanic,
                        &state->tai_offset) == 0)
                state->tai_offset_wait = 0;
        }

        /* Need to abort here if TAI offset is not known */
        if (state->tai_offset_wait)
        {
            log_printf(LOG_ERR, "%s: TAI offset unknown", state->name);
            return SYNC_FAILED;
        }

        /* Update the system TAI offset if changed
         * Note that we don't want to update the system if the TAI offset is
         * not traceable, eg if it was set manually */
        if (last_tai_offset != state->tai_offset)
        {
            log_printf(LOG_INFO, "%s: Updating system TAI offset: %d seconds",
                    state->name, state->tai_offset);
            if (set_tai_offset(state->tai_offset) == -1)
            {
                log_printf(LOG_ERR, "%s: Error setting system TAI offset: %s",
                        state->name, strerror(errno));
                state->tai_offset = last_tai_offset;
            }
            state->invalid = 1;
            return SYNC_FAST_POLL;
        }
    }

    /* Get current system time and hardware time */
    if (ptp_sys_offset(state->clkfd, &sys_time_ns, &hw_time_ns, &lat_ns) == -1)
    {
        log_printf(LOG_ERR,
                "%s: Error reading time from PTP hardware clock: %s",
                state->name, strerror(errno));
        goto clock_error;
    }

    /* Calculate desired offset between system time and hardware time */
    clock_offset_ns = state->add_offset_ns - state->tai_offset * 1000000000LL;

    /* Calculate error in the system time */
    error_ns = (int64_t)sys_time_ns - (int64_t)hw_time_ns - clock_offset_ns;

    /* If there was no previous measurement, update and try again later */
    if (state->invalid)
    {
        state->time_ns = hw_time_ns;
        state->lat_ns = lat_ns;
        state->error_ns = error_ns;
        state->invalid = 0;
        return SYNC_FAST_POLL;
    }

    /* Log a warning if the measurement took an unusually long time */
    if (state->lat_ns != 0 && lat_ns > state->lat_ns * 4)
    {
        log_printf(LOG_WARNING, "%s: Clock reading is unusually slow: "
                "%ld ns (was %ld ns)", state->name, lat_ns, state->lat_ns);
    }

    /* Reset system clock if error is too large (more than 1ms) */
    if (fabs(error_ns) > 1000000)
    {
        if (state->log_reset)
            log_printf(LOG_WARNING, "%s: Clock error exceeds limits, "
                    "resetting system clock: %.0f ns",
                    state->name, error_ns);

        if (set_sys_adj(0) == -1 ||
                set_sys_time(hw_time_ns + clock_offset_ns) == -1)
        {
            if (!state->error_mode)
                log_printf(LOG_ERR, "%s: Error resetting system clock: %s",
                        state->name, strerror(errno));
            goto clock_error;
        }

        state->invalid = 1;
        state->adj = 0;
        state->log_next = 1;
        state->log_reset = 1;
        state->last_log_ns = 0;
        reset_drift(&state->drift);
        reset_error(&state->error);
        return SYNC_FAST_POLL;
    }

    state->log_reset = 1;

    /* Interval between this measurement and last measurement */
    interval_ns = hw_time_ns - state->time_ns;

    /* Get underlying clock drift */
    if (!calc_drift(&state->drift, &drift))
        drift = 0;

    /* Calculate expected change in system clock error since last
     * measurement, based on the current adjustment and estimated drift */
    correction_ns = (drift + state->adj) * interval_ns;

    /* Difference between the measured error and expected error */
    delta_ns = error_ns - (state->error_ns + correction_ns);

    /* If measurement is more than 10ppm from the expected value,
     * start polling at a faster rate until things stabilise */
    if (fabs(delta_ns) > interval_ns * 0.000010)
    {
        fast_poll = 1;
        state->log_next = 1;
    }

    /* Update drift and error with data from new measurement */
    record_drift(&state->drift, drift + delta_ns / interval_ns, interval_ns);
    record_error(&state->error, correction_ns, error_ns);

    /* Get clock error to correct */
    if (!calc_error(&state->error, &med_error_ns))
        med_error_ns = 0;

    /* Set adjustment to compensate for drift and to correct error */
    adj = - drift - med_error_ns /
        (1000000000 * (fast_poll ? SHORT_POLL_INTERVAL : POLL_INTERVAL));

    /* Clamp adjustment to -500ppm .. 500ppm */
    if (adj < -MAX_FREQ_ADJ)
        adj = -MAX_FREQ_ADJ;
    else if (adj > MAX_FREQ_ADJ)
        adj = MAX_FREQ_ADJ;

    /* Warn if the drift component of the adjustment is too high */
    if (fabs(drift) > MAX_FREQ_ADJ)
    {
        log_printf(LOG_ERR, "%s: System clock drift too large: %.3f ppm",
                state->name, drift * 1000000);
    }

    if (set_sys_adj(adj) == -1)
    {
        if (!state->error_mode)
            log_printf(LOG_ERR, "%s: Error adjusting system clock: %s",
                    state->name, strerror(errno));
        goto clock_error;
    }

    /* Store measurements and current adjustment */
    state->time_ns = hw_time_ns;
    state->lat_ns = lat_ns;
    state->error_ns = error_ns;
    state->adj = adj;

    /* Print status */
    if (state->error_mode)
    {
        log_printf(LOG_INFO, "%s: Error state cleared", state->name);
        state->error_mode = 0;
    }
    if (verbose || state->log_next || state->last_log_ns +
            1000000000ULL * LOG_INTERVAL < hw_time_ns)
    {
        log_printf(LOG_INFO, "%s: System clock offset: "
                "%.3f us  drift: %.3f ppm", state->name,
                error_ns * 0.001, drift * 1000000);
        state->last_log_ns = hw_time_ns;

        /* Log again if error is more than 10us */
        state->log_next = (fabs(error_ns) > 10000);
    }

    return fast_poll ? SYNC_FAST_POLL : SYNC_OK;

clock_error:
    state->invalid = 1;
    state->adj = 0;
    state->error_mode = 1;
    state->log_next = 1;
    state->last_log_ns = 0;
    reset_drift(&state->drift);
    reset_error(&state->error);
    return SYNC_FAILED;
}


void shutdown_sys_phc_sync(struct sys_phc_sync_state *state)
{
    double drift;

    log_printf(LOG_INFO, "%s: Stopping system clock discipline using "
            "%s clock", state->name, state->name);

    /* Set adjustment to compensate for drift only */
    if (!calc_drift(&state->drift, &drift))
        drift = 0;
    set_sys_adj(-drift);

    if (state->exanic != NULL)
        exanic_release_handle(state->exanic);

    free(state);
}
