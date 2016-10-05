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
    uint64_t time_ns;   /* Time of last measurement (ns since epoch) */
    int64_t offset_ns;  /* Last measured offset of clock (ns) */
    int invalid;        /* Nonzero if last measurement is not valid */
    double adj;         /* Currently applied adjustment value */
    struct drift drift; /* Estimated drift of the underlying clock */
    int error_mode;     /* Nonzero if there was an error adjusting the clock */
    int log_next;       /* Make sure next measurement is logged */
    int log_reset;      /* Log if clock is reset */
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
        int clkfd, const char *name_src, int clkfd_src)
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

    log_printf(LOG_INFO, "%s: Starting clock discipline using %s clock",
            state->name, state->name_src);

    /* Set up state struct with current time */
    state->time_ns = src_time_ns;
    state->offset_ns = (int64_t)(target_time_ns - src_time_ns);
    state->invalid = 0;
    state->error_mode = 0;
    state->log_next = 1;
    state->log_reset = 0;
    state->last_log = 0;

    /* Use current adjustment as our initial estimate of drift */
    state->adj = adj;
    reset_drift(&state->drift);
    record_drift(&state->drift, -adj, 1000000000 * POLL_INTERVAL);

    return state;
}


enum sync_status poll_phc_phc_sync(struct phc_phc_sync_state *state)
{
    uint64_t src_time_ns, target_time_ns;
    int64_t offset_ns, expected_offset_ns;
    time_t current_time = 0;
    double drift, adj;
    int fast_poll = 0;

    /* Get current time from both hardware clocks */
    if (get_current_time(state->clkfd, state->clkfd_src,
                &target_time_ns, &src_time_ns) == -1)
    {
        log_printf(LOG_ERR,
                "%s: Error reading time from PTP hardware clock: %s",
                state->name, strerror(errno));
        goto clock_error;
    }
    offset_ns = (int64_t)target_time_ns - (int64_t)src_time_ns;
    current_time = src_time_ns / 1000000000;

    /* If there was no previous measurement, update and try again later */
    if (state->invalid)
    {
        state->time_ns = src_time_ns;
        state->offset_ns = offset_ns;
        state->invalid = 0;
        return SYNC_FAST_POLL;
    }

    /* Reset clock if offset is more than 1ms */
    if (offset_ns > 1000000 || offset_ns < -1000000)
    {
        if (state->log_reset)
            log_printf(LOG_WARNING, "%s: Clock error exceeds limits, "
                    "resetting clock: %ld ns",
                    state->name, offset_ns);

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
        return SYNC_FAST_POLL;
    }

    state->log_reset = 1;

    /* Get underlying clock drift */
    calc_drift(&state->drift, &drift);

    /* Calculate expected offset based on the current adjustment and
     * estimated drift */
    expected_offset_ns = state->offset_ns +
        (drift + state->adj) * (src_time_ns - state->time_ns);

    /* If measurement is more than 10ppm from the expected value,
     * start polling at a faster rate until things stabilise */
    if (llabs(expected_offset_ns - offset_ns) >
            (src_time_ns - state->time_ns) / 100000)
    {
        fast_poll = 1;
        state->log_next = 1;
    }

    /* Update drift with data from new measurement */
    record_drift(&state->drift, drift +
            (double)(offset_ns - expected_offset_ns) /
            (src_time_ns - state->time_ns), src_time_ns - state->time_ns);

    /* Set adjustment to compensate for drift and to correct offset */
    adj = - drift - offset_ns /
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
    state->offset_ns = offset_ns;
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
                offset_ns * 0.001, drift * 1000000);
        state->last_log = current_time;

        /* Log again if offset is more than 2us */
        state->log_next = (offset_ns < -2000 || offset_ns > 2000);
    }

    return fast_poll ? SYNC_FAST_POLL : SYNC_OK;

clock_error:
    state->invalid = 1;
    state->adj = 0;
    state->error_mode = 1;
    state->log_next = 1;
    state->log_reset = 1;
    state->last_log = 0;
    reset_drift(&state->drift);
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

    free(state);
}
