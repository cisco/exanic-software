#include <math.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#if HAVE_PTP_CLOCK_H
#include <linux/ptp_clock.h>
#else
#include "../ptp_clock_compat.h"
#endif

#include <exanic/exanic.h>

#include "common.h"
#include "phc_sys.h"


struct phc_sys_sync_state
{
    char name[16];
    int clkfd;
    int64_t add_offset_ns; /* Offset to add to hardware time (ns) */
    int tai_offset;     /* TAI offset to add to hardware time */
    int auto_tai_offset; /* Get TAI offset from system */
    uint64_t time_ns;   /* Time of last measurement (ns since epoch) */
    double error_ns;    /* Last measured clock error (ns) */
    int invalid;        /* Nonzero if last measurement is not valid */
    double adj;         /* Currently applied adjustment value */
    struct drift drift; /* Estimated drift of the underlying clock */
    struct error error; /* Clock error history */
    int error_mode;     /* Nonzero if there was an error adjusting the clock */
    int log_next;       /* Make sure next measurement is logged */
    int log_reset;      /* Log if clock is reset */
    uint64_t last_log_ns; /* Time of last log message (ns since epoch) */
};


static int ptp_sys_offset(int fd, uint64_t *sys_time_ns,
        uint64_t *hw_time_ns)
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

    return 0;
}


struct phc_sys_sync_state *init_phc_sys_sync(const char *name, int fd,
        int tai_offset, int auto_tai_offset, int64_t add_offset_ns)
{
    struct phc_sys_sync_state *state;
    uint64_t sys_time_ns, hw_time_ns;
    double adj;
    int sys_tai_offset = 0;

    /* First check that the ioctl works */
    if (ptp_sys_offset(fd, &sys_time_ns, &hw_time_ns) == -1)
    {
        log_printf(LOG_ERR,
                "%s: Error reading time from PTP hardware clock: %s",
                name, strerror(errno));
        return NULL;
    }

    if (get_clock_adj(fd, &adj) == -1)
    {
        log_printf(LOG_ERR, "%s: Error reading current adjustment: %s",
                name, strerror(errno));
        return NULL;
    }

    if (auto_tai_offset && get_tai_offset(&sys_tai_offset) == -1)
    {
        log_printf(LOG_ERR, "%s: Error reading TAI offset from system: %s",
                name, strerror(errno));
        return NULL;
    }

    state = malloc(sizeof(struct phc_sys_sync_state));

    snprintf(state->name, sizeof(state->name), "%s", name);
    state->clkfd = fd;

    /* Time offset settings */
    state->add_offset_ns = add_offset_ns;
    state->tai_offset = auto_tai_offset ? sys_tai_offset : tai_offset;
    state->auto_tai_offset = auto_tai_offset;

    log_printf(LOG_INFO, "%s: Starting clock discipline using system clock",
            state->name);
    log_printf(LOG_INFO, "%s: Current TAI offset is %d", state->name,
            state->tai_offset);

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


enum sync_status poll_phc_sys_sync(struct phc_sys_sync_state *state)
{
    uint64_t sys_time_ns, hw_time_ns;
    double error_ns, interval_ns, correction_ns, delta_ns, avg_error_ns;
    double drift, adj;
    int64_t clock_offset_ns;
    int fast_poll = 0;

    /* Get current system time and hardware time */
    if (ptp_sys_offset(state->clkfd, &sys_time_ns, &hw_time_ns) == -1)
    {
        log_printf(LOG_ERR,
                "%s: Error reading time from PTP hardware clock: %s",
                state->name, strerror(errno));
        goto clock_error;
    }

    /* Calculate desired offset between system time and hardware time */
    if (state->auto_tai_offset)
    {
        if (get_tai_offset(&state->tai_offset) == -1)
        {
            log_printf(LOG_ERR,
                    "%s: Error reading TAI offset from system: %s",
                    state->name, strerror(errno));
            goto clock_error;
        }
    }
    clock_offset_ns = state->add_offset_ns + state->tai_offset * 1000000000LL;

    /* Current error in the hardware time */
    error_ns = (int64_t)hw_time_ns - (int64_t)sys_time_ns - clock_offset_ns;

    /* If there was no previous measurement, update and try again later */
    if (state->invalid)
    {
        state->time_ns = hw_time_ns;
        state->error_ns = error_ns;
        state->invalid = 0;
        return SYNC_FAST_POLL;
    }

    /* Reset hardware clock if offset is too large (more than 1ms) */
    if (fabs(error_ns) > 1000000)
    {
        if (state->log_reset)
            log_printf(LOG_WARNING, "%s: Clock error exceeds limits, "
                    "resetting clock: %.0f ns",
                    state->name, error_ns);

        if (set_clock_adj(state->clkfd, 0) == -1 ||
                set_clock_time(state->clkfd,
                    sys_time_ns + clock_offset_ns) == -1)
        {
            if (!state->error_mode)
                log_printf(LOG_ERR, "%s: Error resetting clock: %s",
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
    interval_ns = sys_time_ns - state->time_ns;

    /* Get underlying clock drift */
    calc_drift(&state->drift, &drift);

    /* Calculate expected change in hardware clock error based on
     * the current adjustment and estimated drift */
    correction_ns = (drift + state->adj) * (sys_time_ns - state->time_ns);

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
    calc_error(&state->error, &avg_error_ns);

    /* Set adjustment to compensate for drift and to correct error */
    adj = - drift - avg_error_ns /
        (1000000000 * (fast_poll ? SHORT_POLL_INTERVAL : POLL_INTERVAL));
    if (set_clock_adj(state->clkfd, adj) == -1)
    {
        if (!state->error_mode)
            log_printf(LOG_ERR, "%s: Error adjusting clock: %s",
                    state->name, strerror(errno));
        goto clock_error;
    }

    /* Store measurements and current adjustment */
    state->time_ns = sys_time_ns;
    state->error_ns = error_ns;
    state->adj = adj;

    /* Print status */
    if (state->error_mode)
    {
        log_printf(LOG_INFO, "%s: Error state cleared", state->name);
        state->error_mode = 0;
    }
    if (verbose || state->log_next || state->last_log_ns +
            1000000000ULL * LOG_INTERVAL < sys_time_ns)
    {
        log_printf(LOG_INFO, "%s: Clock offset from system: %.3f us "
                " drift: %.3f ppm", state->name,
                error_ns * 0.001, drift * 1000000);
        state->last_log_ns = sys_time_ns;

        /* Log again if offset is more than 10us */
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
    return SYNC_FAILED;
}


void shutdown_phc_sys_sync(struct phc_sys_sync_state *state)
{
    double drift;

    log_printf(LOG_INFO, "%s: Stopping clock discipline using system clock",
            state->name);

    /* Set adjustment to compensate for drift only */
    calc_drift(&state->drift, &drift);
    set_clock_adj(state->clkfd, -drift);

    free(state);
}
