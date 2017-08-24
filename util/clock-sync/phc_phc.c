#include <math.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>

#include <exanic/exanic.h>

#include "common.h"
#include "phc_phc.h"

#define SAMPLES 8


struct phc_phc_sync_state
{
    char name[16];
    int clkfd;
    char name_src[16];
    int clkfd_src;
    struct exanic *exanic_src;
    enum phc_source phc_source;
    uint64_t time_ns;   /* Time of last measurement (ns since epoch) */
    double error_ns;    /* Last measured clock error (ns) */
    int invalid;        /* Nonzero if last measurement is not valid */
    double adj;         /* Currently applied adjustment value */
    struct drift drift; /* Estimated drift of the underlying clock */
    struct error error; /* Clock error history */
    int error_mode;     /* Nonzero if there was an error adjusting the clock */
    int log_next;       /* Make sure next measurement is logged */
    int log_reset;      /* Log if clock is reset */
    int init_wait;      /* Nonzero if waiting for source to be synced */
    time_t last_log;    /* Time of last log message (s since epoch) */
};


/* Get current time from both hardware clocks */
static int get_current_time(int clkfd, int clkfd_src,
        uint64_t *target_time_ns, uint64_t *src_time_ns)
{
    int i;
    uint64_t e1, e2, s1, s2;
    uint64_t d = ~0;

    /* For each sample we read both clocks twice in different order to
     * cancel out latency
     * The reading with the smallest interval is selected
     */
    for (i = 0; i < SAMPLES; i++)
    {
        if (get_clock_time(clkfd_src, &s1) == -1 ||
                get_clock_time(clkfd, &e1) == -1 ||
                get_clock_time(clkfd, &e2) == -1 ||
                get_clock_time(clkfd_src, &s2) == -1)
            return -1;

        if (d == ~0 || (s2 - s1) < d)
        {
            d = s2 - s1;
            *target_time_ns = (e1 + e2) / 2;
            *src_time_ns = (s1 + s2) / 2;
        }
    }

    return 0;
}


struct phc_phc_sync_state *init_phc_phc_sync(const char *name,
        int clkfd, const char *name_src, int clkfd_src, exanic_t *exanic_src)
{
    struct phc_phc_sync_state *state;
    uint64_t src_time_ns, target_time_ns;
    double adj;

    /* First check that we can get the time from both clocks */
    if (get_current_time(clkfd, clkfd_src, &target_time_ns, &src_time_ns) == -1)
    {
        log_printf(LOG_ERR,
                "%s: Error reading time from PTP hardware clock: %s",
                name, strerror(errno));
        return NULL;
    }

    if (get_clock_adj(clkfd, &adj) == -1)
    {
        log_printf(LOG_ERR, "%s: Error reading current adjustment: %s",
                name, strerror(errno));
        return NULL;
    }

    state = malloc(sizeof(struct phc_phc_sync_state));

    snprintf(state->name, sizeof(state->name), "%s", name);
    snprintf(state->name_src, sizeof(state->name_src), "%s", name_src);
    state->clkfd = clkfd;
    state->clkfd_src = clkfd_src;
    state->exanic_src = exanic_src;
    state->phc_source = get_phc_source(clkfd_src, exanic_src);

    log_printf(LOG_INFO, "%s: Starting clock discipline using %s clock",
            state->name, state->name_src);

    if (state->phc_source == PHC_SOURCE_EXANIC_GPS)
    {
        log_printf(LOG_INFO, "%s: Waiting for GPS sync on %s clock",
                state->name, state->name_src);
        state->init_wait = 1;
    }
    else if (state->phc_source == PHC_SOURCE_SYNC)
    {
        log_printf(LOG_INFO, "%s: Waiting for sync on %s clock",
                state->name, state->name_src);
        state->init_wait = 1;
    }
    else
        state->init_wait = 0;

    /* Set up state struct with current time */
    state->time_ns = src_time_ns;
    state->invalid = 1;
    state->error_mode = 0;
    state->log_next = 1;
    state->log_reset = 0;
    state->last_log = 0;

    /* Use current adjustment as our initial estimate of drift */
    state->adj = adj;
    reset_drift(&state->drift);
    record_drift(&state->drift, -adj, 1000000000 * POLL_INTERVAL);

    /* Record current error measurement in error history */
    reset_error(&state->error);

    update_phc_status(clkfd, PHC_STATUS_UNKNOWN);

    return state;
}


enum sync_status poll_phc_phc_sync(struct phc_phc_sync_state *state)
{
    uint64_t src_time_ns, target_time_ns;
    time_t current_time = 0;
    double error_ns, interval_ns, correction_ns, delta_ns, med_error_ns;
    double drift, adj;
    int fast_poll = 0;

    /* Check if we are still waiting for source clock to be ready */
    if (state->init_wait)
    {
        if (state->phc_source == PHC_SOURCE_EXANIC_GPS)
        {
            /* Waiting for GPS sync on the source ExaNIC clock */
            if (check_exanic_gps_time(state->exanic_src) == 0)
            {
                log_printf(LOG_INFO, "%s: GPS sync acquired on %s clock",
                        state->name, state->name_src);
                state->init_wait = 0;
            }
        }
        else if (state->phc_source == PHC_SOURCE_SYNC)
        {
            /* Waiting for source clock to be synced */
            if (get_phc_status(state->clkfd_src) == PHC_STATUS_SYNCED)
            {
                log_printf(LOG_INFO, "%s: Detected clock sync on %s clock",
                        state->name, state->name_src);
                state->init_wait = 0;
            }
        }

        /* Source clock is not ready */
        if (state->init_wait)
            return SYNC_FAILED;
    }

    /* Get current time from both hardware clocks */
    if (get_current_time(state->clkfd, state->clkfd_src,
                &target_time_ns, &src_time_ns) == -1)
    {
        log_printf(LOG_ERR,
                "%s: Error reading time from PTP hardware clock: %s",
                state->name, strerror(errno));
        goto clock_error;
    }
    error_ns = (int64_t)target_time_ns - (int64_t)src_time_ns;
    current_time = src_time_ns / 1000000000;

    /* If there was no previous measurement, update and try again later */
    if (state->invalid)
    {
        state->time_ns = src_time_ns;
        state->error_ns = error_ns;
        state->invalid = 0;
        return SYNC_FAST_POLL;
    }

    /* Reset clock if error is more than 1ms */
    if (fabs(error_ns) > 1000000)
    {
        if (state->log_reset)
            log_printf(LOG_WARNING, "%s: Clock error exceeds limits, "
                    "resetting clock: %ld ns",
                    state->name, error_ns);

        if (set_clock_adj(state->clkfd, 0) == -1 ||
                set_clock_time(state->clkfd, src_time_ns) == -1)
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
        state->last_log = 0;
        reset_drift(&state->drift);
        reset_error(&state->error);
        update_phc_status(state->clkfd, PHC_STATUS_UNKNOWN);
        return SYNC_FAST_POLL;
    }

    state->log_reset = 1;

    /* Interval between this measurement and last measurement */
    interval_ns = src_time_ns - state->time_ns;

    /* Get underlying clock drift */
    calc_drift(&state->drift, &drift);

    /* Calculate expected change in clock error since last measurement,
     * based on the current adjustment and estimated drift */
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
    calc_error(&state->error, &med_error_ns);

    /* Set adjustment to compensate for drift and to correct error */
    adj = - drift - med_error_ns /
        (1000000000 * (fast_poll ? SHORT_POLL_INTERVAL : POLL_INTERVAL));
    if (set_clock_adj(state->clkfd, adj) == -1)
    {
        if (!state->error_mode)
            log_printf(LOG_ERR, "%s: Error adjusting clock: %s",
                    state->name, strerror(errno));
        goto clock_error;
    }

    /* Store measurements and current adjustment */
    state->time_ns = src_time_ns;
    state->error_ns = error_ns;
    state->adj = adj;

    /* Print status */
    if (state->error_mode)
    {
        log_printf(LOG_INFO, "%s: Error state cleared", state->name);
        state->error_mode = 0;
    }
    if (verbose || state->log_next ||
            state->last_log + LOG_INTERVAL <= current_time)
    {
        log_printf(LOG_INFO, "%s: Clock offset from %s: %.3f us "
                " drift: %.3f ppm", state->name, state->name_src,
                error_ns * 0.001, drift * 1000000);
        state->last_log = current_time;

        /* Log again if error is more than 2us */
        state->log_next = (fabs(error_ns) > 2000);
    }

    update_phc_status(state->clkfd, PHC_STATUS_SYNCED);

    return fast_poll ? SYNC_FAST_POLL : SYNC_OK;

clock_error:
    state->invalid = 1;
    state->adj = 0;
    state->error_mode = 1;
    state->log_next = 1;
    state->log_reset = 1;
    state->last_log = 0;
    reset_drift(&state->drift);
    reset_error(&state->error);
    update_phc_status(state->clkfd, PHC_STATUS_UNKNOWN);
    return SYNC_FAILED;
}


void shutdown_phc_phc_sync(struct phc_phc_sync_state *state)
{
    double drift;

    log_printf(LOG_INFO, "%s: Stopping clock discipline using %s clock",
            state->name, state->name_src);

    /* Set adjustment to compensate for drift only */
    calc_drift(&state->drift, &drift);
    set_clock_adj(state->clkfd, -drift);

    if (state->exanic_src != NULL)
        exanic_release_handle(state->exanic_src);

    free(state);
}
