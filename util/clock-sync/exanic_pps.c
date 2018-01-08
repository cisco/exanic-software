#include <math.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <sys/time.h>

#include <exanic/exanic.h>
#include <exanic/pcie_if.h>
#include <exanic/register.h>
#include <exanic/util.h>

#include "common.h"
#include "exanic_pps.h"

#define LEN 8
#define SKIP_MAX 5
#define TIMEOUT_SECONDS 10
#define ERROR_MAX 0.001


struct exanic_pps_sync_state
{
    char name[16];
    int clkfd;
    exanic_t *exanic;
    uint32_t tick_hz;   /* Nominal frequency of clock (ticks/second) */
    int64_t offset_ns;  /* Offset to add to ExaNIC time (ns) */
    int tai_offset;     /* TAI offset to add to ExaNIC time */
    int auto_tai_offset; /* Get TAI offset from system */
    unsigned interval;  /* Averaging interval (s) */
    uint64_t pps_time_tick; /* Time of last PPS */
    uint64_t adj_time_tick; /* Time of last change to adjustment value */
    double tick_adj;    /* Number of extra clock ticks at the last adjustment */
    uint32_t pps_reg;   /* Last seen value of the PPS register */
    time_t pps_time;    /* Time of last PPS pulse (seconds since epoch) */
    double pps_offset;  /* Offset at last PPS pulse (ns) */
    double adj;         /* Currently applied adjustment value */
    struct rate_error rate; /* Clock error measurements */
    int error_mode;     /* Nonzero if there was an error adjusting the clock */
    int pps_signal;     /* 0 = no signal, 1 = signal, -1 = indeterminate */
    int log_next;       /* Make sure next measurement is logged */
    int log_reset;      /* Log if clock is reset */
    uint64_t last_log_ns; /* Time of last log message (ns since epoch) */
    time_t pps_last_seen; /* Time of last poll that a PPS pulse was detected
                             (CLOCK_MONOTONIC) */
};


struct exanic_pps_sync_state *init_exanic_pps_sync(const char *name, int clkfd,
        exanic_t *exanic, enum pps_type pps_type, int pps_termination_disable,
        enum pps_edge pps_edge, int tai_offset, int auto_tai_offset,
        int64_t offset_ns, unsigned interval)
{
    struct exanic_pps_sync_state *state;
    exanic_hardware_id_t hw_id;
    struct timespec ts_mono;
    uint64_t time_ns;
    double adj;
    int sys_tai_offset;

    /* First get the hardware clock time and current adjustment */
    if (get_clock_time(clkfd, &time_ns) == -1)
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

    if (auto_tai_offset && get_tai_offset(&sys_tai_offset) == -1)
    {
        log_printf(LOG_ERR, "%s: Error reading TAI offset from system: %s",
                name, strerror(errno));
        return NULL;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_mono);

    state = malloc(sizeof(struct exanic_pps_sync_state));

    exanic_retain_handle(exanic);

    snprintf(state->name, sizeof(state->name), "%s", name);
    state->clkfd = clkfd;
    state->exanic = exanic;
    state->tick_hz = exanic_register_read(state->exanic,
            REG_EXANIC_INDEX(REG_EXANIC_CLK_HZ));

    /* Check for invalid settings */
    hw_id = exanic_get_hw_type(exanic);
    if ((hw_id == EXANIC_HW_Z1 || hw_id == EXANIC_HW_Z10) &&
            pps_type == PPS_SINGLE_ENDED)
    {
        log_printf(LOG_WARNING, "%s: %s does not support single-ended PPS input",
                state->name, exanic_hardware_id_str(hw_id));
        pps_type = PPS_DIFFERENTIAL;
    }
    else if (((hw_id == EXANIC_HW_X10) || (hw_id == EXANIC_HW_X10_GM) ||
                (hw_id == EXANIC_HW_X40 || (hw_id == EXANIC_HW_V5P) )) &&
            pps_type == PPS_DIFFERENTIAL)
    {
        log_printf(LOG_WARNING, "%s: %s does not support differential PPS input",
                state->name, exanic_hardware_id_str(hw_id));
        pps_type = PPS_SINGLE_ENDED;
    }

    state->interval = interval;

    /* Time offset settings */
    state->offset_ns = offset_ns;
    state->tai_offset = auto_tai_offset ? sys_tai_offset : tai_offset;
    state->auto_tai_offset = auto_tai_offset;

    log_printf(LOG_INFO, "%s: Starting clock discipline using PPS",
            state->name);
    log_printf(LOG_INFO, "%s: Nominal frequency: %u Hz",
            state->name, state->tick_hz);
    log_printf(LOG_INFO, "%s: Using %s PPS input", state->name,
            pps_type == PPS_SINGLE_ENDED ? "single-ended" : "differential");
    log_printf(LOG_INFO, "%s: Setting PPS termination %s", state->name,
            pps_termination_disable ? "disabled" : "enabled");
    log_printf(LOG_INFO, "%s: Syncing to PPS %s edge", state->name,
            pps_edge == PPS_RISING_EDGE ? "rising" : "falling");
    log_printf(LOG_INFO, "%s: Current TAI offset is %d", state->name,
            state->tai_offset);
    log_printf(LOG_INFO, "%s: Averaging interval: %d s", state->name,
            state->interval);

    /* PPS settings */
    if ((hw_id == EXANIC_HW_X4) || (hw_id == EXANIC_HW_X2))
    {
        uint32_t reg;

        reg = exanic_register_read(state->exanic, REG_HW_INDEX(REG_HW_SERIAL_PPS));

        if (pps_type == PPS_SINGLE_ENDED)
            reg |= EXANIC_HW_SERIAL_PPS_SINGLE;
        else
            reg &= ~EXANIC_HW_SERIAL_PPS_SINGLE;

        if (pps_edge == PPS_RISING_EDGE)
            reg |= EXANIC_HW_SERIAL_PPS_EDGE_SEL;
        else
            reg &= ~EXANIC_HW_SERIAL_PPS_EDGE_SEL;

        exanic_register_write(state->exanic, REG_HW_INDEX(REG_HW_SERIAL_PPS), reg);
    }
    else if ((hw_id == EXANIC_HW_X10) || (hw_id == EXANIC_HW_X10_GM) ||
            (hw_id == EXANIC_HW_X40))  /* PPS Termination Settings */
    {
        uint32_t reg;

        reg = exanic_register_read(state->exanic, REG_HW_INDEX(REG_HW_SERIAL_PPS));

        if (pps_termination_disable)
            reg &= ~EXANIC_HW_SERIAL_PPS_TERM_EN;
        else
            reg |= EXANIC_HW_SERIAL_PPS_TERM_EN;

        if (pps_edge == PPS_RISING_EDGE)
            reg |= EXANIC_HW_SERIAL_PPS_EDGE_SEL;
        else
            reg &= ~EXANIC_HW_SERIAL_PPS_EDGE_SEL;

        reg &= ~EXANIC_HW_SERIAL_PPS_OUT_EN;

        exanic_register_write(state->exanic, REG_HW_INDEX(REG_HW_SERIAL_PPS), reg);
    }

    /* Don't allow too large adjustments as the algorithm cannot handle it */
    if (fabs(adj) > ERROR_MAX)
    {
        log_printf(LOG_WARNING, "%s: Current adjustment out of range, "
                "resetting to 0", state->name);
        set_clock_adj(state->clkfd, 0);
        adj = 0;
    }

    /* Set up state struct */
    state->pps_time_tick = 0;
    state->adj_time_tick = 0;
    state->tick_adj = 0;

    state->pps_reg = exanic_register_read(state->exanic,
            REG_EXANIC_INDEX(REG_EXANIC_PPS_TIMESTAMP));
    state->pps_offset = 0;
    state->pps_time = 0;

    /* Get current adjustment from exanic */
    state->adj = adj;

    state->error_mode = 0;
    state->pps_signal = -1;
    state->log_next = 1;
    state->log_reset = 0;
    state->last_log_ns = 0;
    state->pps_last_seen = ts_mono.tv_sec;
    reset_rate_error(&state->rate, state->interval);

    update_phc_status(clkfd, PHC_STATUS_UNKNOWN);

    return state;
}


enum sync_status poll_exanic_pps_sync(struct exanic_pps_sync_state *state)
{
    struct timespec ts_mono, ts_sys;
    uint32_t pps_reg;
    uint64_t poll_time_ns = 0;
    uint64_t poll_time_tick;
    int32_t poll_time_tick_hi, poll_time_tick_lo;
    int good_pps_seen = 0;
    double rate_error, adev;
    int rate_error_known, adev_known;

    clock_gettime(CLOCK_MONOTONIC, &ts_mono);
    clock_gettime(CLOCK_REALTIME, &ts_sys);

    /* Read the latched timestamp value at the last PPS pulse
     * This must be done before reading the current hardware time */
    pps_reg = exanic_register_read(state->exanic, REG_EXANIC_INDEX(
                REG_EXANIC_PPS_TIMESTAMP));
    if (pps_reg != exanic_register_read(state->exanic, REG_EXANIC_INDEX(
                REG_EXANIC_PPS_TIMESTAMP)))
    {
        /* Reading was unstable, this indicates PPS pulse may have
         * arrived while we were reading
         * To avoid errors, pretend that the register value has not changed
         * The PPS pulse will be handled next time we poll the register */
        pps_reg = state->pps_reg;
    }

    /* Get current time from hardware clock */
    if (get_clock_time(state->clkfd, &poll_time_ns) == -1)
    {
        log_printf(LOG_ERR,
                "%s: Error reading time from PTP hardware clock: %s",
                state->name, strerror(errno));
        goto clock_error;
    }

    /* Calculate current time in ticks since epoch */
    poll_time_tick = (poll_time_ns / 1000000000) * state->tick_hz +
        (poll_time_ns % 1000000000) * state->tick_hz / 1000000000;
    poll_time_tick_hi = (poll_time_tick >> 32);
    poll_time_tick_lo = (poll_time_tick & 0xFFFFFFFF);

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

    if (pps_reg != state->pps_reg)
    {
        uint64_t pps_time_tick, desired_time_tick;
        uint64_t pps_sys_time_ns;
        double pps_offset;
        time_t time_sec;
        int good_interval;

        /* Record that we have seen a PPS pulse */
        if (state->pps_signal != 1)
        {
            log_printf(LOG_INFO, "%s: PPS signal detected",
                    state->name);
        }
        state->pps_signal = 1;
        state->pps_last_seen = ts_mono.tv_sec;

        /* Extend the PPS pulse time to 64 bits
         * This calculation assumes the PPS pulse time is before the current
         * hardware time, within one rollover period */
        if (poll_time_tick_lo < pps_reg)
            pps_time_tick = ((uint64_t)(poll_time_tick_hi - 1) << 32) | pps_reg;
        else
            pps_time_tick = ((uint64_t)poll_time_tick_hi << 32) | pps_reg;

        /* Calculate the system time at PPS pulse, and use the calculated time
         * to find the nearest second boundary */
        pps_sys_time_ns = ts_sys.tv_sec * 1000000000ULL + ts_sys.tv_nsec -
            (poll_time_tick - pps_time_tick) * 1000000000ULL / state->tick_hz;
        time_sec = (pps_sys_time_ns + 500000000) / 1000000000;

        /* Convert from UTC timescale to TAI timescale */
        time_sec += state->tai_offset;

        /* What the PPS pulse time should be, in ticks since epoch */
        desired_time_tick = (uint64_t)time_sec * state->tick_hz +
            state->offset_ns;

        /* Calculate offset (ns) from the desired time */
        if (pps_time_tick > desired_time_tick)
            pps_offset = (pps_time_tick - desired_time_tick) * 1000000000.0 /
                state->tick_hz;
        else
            pps_offset = (desired_time_tick - pps_time_tick) * -1000000000.0 /
                state->tick_hz;

        /* Measure interval between consecutive PPS in raw ticks */
        good_interval = 0;
        if (state->pps_time_tick != 0 && pps_time_tick > state->pps_time_tick)
        {
            uint64_t ticks = pps_time_tick - state->pps_time_tick;
            unsigned seconds = round(1.0 * ticks / state->tick_hz);
            uint64_t desired_ticks = (uint64_t)seconds * state->tick_hz;
            int64_t tick_err;
            double tick_adj, raw_tick_err;

            /* Difference between the expected and actual number of ticks */
            if (ticks > desired_ticks)
                tick_err = ticks - desired_ticks;
            else
                tick_err = -(int64_t)(desired_ticks - ticks);

            /* Subtract out clock adjustment to get raw tick count */
            tick_adj = state->tick_adj;
            if (pps_time_tick > state->adj_time_tick)
            {
                tick_adj += (pps_time_tick - state->adj_time_tick) *
                    state->adj / (state->adj + 1);
            }
            raw_tick_err = tick_err - tick_adj;

            if (seconds > SKIP_MAX)
            {
                log_printf(LOG_WARNING, "%s: PPS interval too large: %d s",
                        state->name, seconds);
            }
            else if (fabs(raw_tick_err) > ERROR_MAX * seconds * state->tick_hz)
            {
                log_printf(LOG_WARNING, "%s: Ignoring possible spurious PPS, "
                        "error measurement: %.4f ticks",
                        state->name, raw_tick_err);
            }
            else if (fabs(tick_adj) > fabs(raw_tick_err) * 10)
            {
                /* Raw tick measurement is inaccurate when clock adjustment
                 * is large, so don't record it */
                good_interval = 1;
            }
            else
            {
                record_rate_error(&state->rate, raw_tick_err / state->tick_hz,
                        seconds);
                good_interval = 1;
            }
        }

        /* Update state for measuring PPS interval */
        state->pps_time_tick = pps_time_tick;
        state->adj_time_tick = pps_time_tick;
        state->tick_adj = 0;

        /* Record PPS offset measurement if it is good */
        if (good_interval || state->pps_time == 0)
        {
            state->pps_offset = pps_offset;
            state->pps_time = time_sec;
            good_pps_seen = 1;
        }

        state->pps_reg = pps_reg;
    }

    /* Check if we haven't seen a PPS pulse for a while */
    if (ts_mono.tv_sec - state->pps_last_seen > TIMEOUT_SECONDS)
    {
        if (state->pps_signal == -1)
        {
            log_printf(LOG_WARNING, "%s: No PPS signal detected",
                    state->name);
        }
        else if (state->pps_signal != 0)
        {
            log_printf(LOG_WARNING, "%s: PPS signal lost",
                    state->name);
        }

        state->pps_signal = 0;
        state->log_next = 1;
    }

    /* Calculate average rate error and allan deviation using the chosen
     * averaging period */
    rate_error_known = calc_rate_error(&state->rate, &rate_error);
    adev_known = calc_rate_error_adev(&state->rate, &adev);

    /* Logging */
    if (good_pps_seen)
    {
        /* If offset is more than 1us, make sure status is logged */
        if (fabs(state->pps_offset) > 1000)
            state->log_next = 1;

        if (verbose || state->log_next || state->last_log_ns +
                LOG_INTERVAL * 1000000000ULL < poll_time_ns)
        {
            if (!rate_error_known)
            {
                log_printf(LOG_INFO, "%s: Clock offset at PPS pulse: "
                        "%.4f us", state->name, state->pps_offset * 0.001);
            }
            else if (!adev_known)
            {
                log_printf(LOG_INFO, "%s: Clock offset at PPS pulse: "
                        "%.4f us  drift: %.4f ppm", state->name,
                        state->pps_offset * 0.001, rate_error * 1000000);
            }
            else
            {
                log_printf(LOG_INFO, "%s: Clock offset at PPS pulse: "
                        "%.4f us  drift: %.4f ppm  adev: %.3e",
                        state->name, state->pps_offset * 0.001,
                        rate_error * 1000000, adev);
            }
            state->last_log_ns = poll_time_ns;
        }

        /* Slow down logging if offset is less than 1us */
        if (fabs(state->pps_offset) < 1000)
            state->log_next = 0;
    }

    if (fabs(state->pps_offset) > 1000000)
    {
        /* Offset is more than 1ms, reset clock */
        if (state->log_reset)
            log_printf(LOG_WARNING, "%s: Clock error exceeds limits, "
                    "resetting clock: %.4f us",
                    state->name, state->pps_offset * 0.001);

        if (set_clock_adj(state->clkfd, 0) == -1)
        {
            if (!state->error_mode)
                log_printf(LOG_ERR, "%s: Error resetting clock adjustment: %s",
                        state->name, strerror(errno));
            goto clock_error;
        }

        if (fabs(state->pps_offset) > 100000000)
        {
            /* Set time directly */
            uint64_t time_ns = poll_time_ns - state->pps_offset;
            if (set_clock_time(state->clkfd, time_ns) == -1)
            {
                if (!state->error_mode)
                    log_printf(LOG_ERR, "%s: Error setting clock time: %s",
                            state->name, strerror(errno));
                goto clock_error;
            }
        }
        else
        {
            /* Set time by offset from current time */
            if (set_clock_time_offset(state->clkfd,
                        (long)-state->pps_offset) == -1)
            {
                if (!state->error_mode)
                    log_printf(LOG_ERR, "%s: Error setting clock time: %s",
                            state->name, strerror(errno));
                goto clock_error;
            }
        }

        state->pps_time_tick = 0;
        state->adj_time_tick = 0;
        state->tick_adj = 0;
        state->pps_offset = 0;
        state->pps_time = 0;
        state->adj = 0;
        state->log_next = 1;
        state->log_reset = 1;
        state->last_log_ns = poll_time_ns;
        /* Rate error history is not reset because rate error measurements
         * should still be valid */

        update_phc_status(state->clkfd, PHC_STATUS_UNKNOWN);

        return SYNC_OK;
    }
    else
    {
        /* Adjust clock rate to compensate for offset and rate error */
        double offset_correction;
        int64_t time_since_pps_ns;
        double adj;

        /* Measure time since last PPS pulse */
        time_since_pps_ns = poll_time_ns - state->pps_time * 1000000000ULL;
        if (time_since_pps_ns < 3 * PPS_POLL_INTERVAL * 1000000000ULL)
            /* Add offset correction */
            offset_correction = - state->pps_offset /
                (3 * PPS_POLL_INTERVAL * 1000000000LL);
        else
            /* Don't add offset correction, it should be corrected by now */
            offset_correction = 0;

        adj = offset_correction - (rate_error_known ? rate_error : 0);
        if (set_clock_adj(state->clkfd, adj) == -1)
        {
            if (!state->error_mode)
                log_printf(LOG_ERR, "%s: Error adjusting clock: %s",
                        state->name, strerror(errno));
            goto clock_error;
        }

        /* Record adjustment and update raw tick counters */
        if (poll_time_tick > state->adj_time_tick)
        {
            state->tick_adj += (poll_time_tick - state->adj_time_tick) *
                state->adj / (state->adj + 1);
            state->adj_time_tick = poll_time_tick;
        }
        state->adj = adj;

        /* If we get here, everything is working correctly */
        if (state->error_mode)
        {
            log_printf(LOG_INFO, "%s: Error state cleared", state->name);
            state->error_mode = 0;
        }

        state->log_reset = 1;

        if (state->pps_signal == 1)
        {
            update_phc_status(state->clkfd, PHC_STATUS_SYNCED);
            return SYNC_OK;
        }
        else
        {
            update_phc_status(state->clkfd, PHC_STATUS_HOLDOVER);
            return SYNC_FAILED;
        }
    }

clock_error:
    state->pps_time_tick = 0;
    state->adj_time_tick = 0;
    state->tick_adj = 0;
    state->pps_offset = 0;
    state->pps_time = 0;
    state->adj = 0;
    state->error_mode = 1;
    state->log_next = 1;
    state->log_reset = 1;
    state->last_log_ns = 0;
    reset_rate_error(&state->rate, state->interval);
    update_phc_status(state->clkfd, PHC_STATUS_UNKNOWN);
    return SYNC_FAILED;
}


void shutdown_exanic_pps_sync(struct exanic_pps_sync_state *state)
{
    double rate_error = 0;

    log_printf(LOG_INFO, "%s: Stopping clock discipline using PPS",
            state->name);

    /* Set adjustment to compensate for rate error only */
    calc_rate_error(&state->rate, &rate_error);
    set_clock_adj(state->clkfd, -rate_error);

    exanic_release_handle(state->exanic);

    free(state);

}
