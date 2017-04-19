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
#define SPURIOUS_MAX 3
#define TIMEOUT_SECONDS 10


struct exanic_pps_sync_state
{
    char name[16];
    int clkfd;
    exanic_t *exanic;
    uint32_t tick_hz;   /* Nominal frequency of clock (ticks/second) */
    int64_t offset_ns;  /* Offset to add to ExaNIC time (ns) */
    int tai_offset;     /* TAI offset to add to ExaNIC time */
    int auto_tai_offset; /* Get TAI offset from system */
    uint64_t poll_time_ns; /* Time of last poll (ns since epoch) */
    uint32_t pps_reg;   /* Last seen value of the PPS register */
    time_t pps_time;    /* Time of last PPS pulse (seconds since epoch) */
    double pps_offset;  /* Offset at last PPS pulse (ns) */
    double adj;         /* Currently applied adjustment value */
    struct drift drift; /* Estimated drift of the underlying clock */
    int error_mode;     /* Nonzero if there was an error adjusting the clock */
    int pps_signal;     /* 0 = no signal, 1 = signal, -1 = indeterminate */
    int log_next;       /* Make sure next measurement is logged */
    int log_reset;      /* Log if clock is reset */
    uint64_t last_log_ns; /* Time of last log message (ns since epoch) */
    time_t pps_last_seen; /* Time of last poll that a PPS pulse was detected
                             (CLOCK_MONOTONIC) */
    int spurious_pps_count; /* Number of consecutive spurious PPS pulses */
};


struct exanic_pps_sync_state *init_exanic_pps_sync(const char *name, int clkfd,
        exanic_t *exanic, enum pps_type pps_type, int pps_termination_disable,
        int tai_offset, int auto_tai_offset, int64_t offset_ns)
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
                (hw_id == EXANIC_HW_X40)) &&
            pps_type == PPS_DIFFERENTIAL)
    {
        log_printf(LOG_WARNING, "%s: %s does not support differential PPS input",
                state->name, exanic_hardware_id_str(hw_id));
        pps_type = PPS_SINGLE_ENDED;
    }

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
    log_printf(LOG_INFO, "%s: Current TAI offset is %d", state->name,
            state->tai_offset);

    /* PPS settings */
    if ((hw_id == EXANIC_HW_X4) || (hw_id == EXANIC_HW_X2))
    {
        uint32_t reg;

        reg = exanic_register_read(state->exanic, REG_HW_INDEX(REG_HW_SERIAL_PPS));
        if (pps_type == PPS_SINGLE_ENDED)
            reg |= EXANIC_HW_SERIAL_PPS_SINGLE;
        else
            reg &= ~EXANIC_HW_SERIAL_PPS_SINGLE;

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
        reg &= ~EXANIC_HW_SERIAL_PPS_OUT_EN;

        exanic_register_write(state->exanic, REG_HW_INDEX(REG_HW_SERIAL_PPS), reg);
    }

    /* Set up state struct */
    state->poll_time_ns = time_ns;

    state->pps_reg = exanic_register_read(state->exanic,
            REG_EXANIC_INDEX(REG_EXANIC_PPS_TIMESTAMP));
    state->pps_time = 0;
    state->pps_offset = 0;

    /* Get current adjustment from exanic */
    state->adj = adj;

    state->error_mode = 0;
    state->pps_signal = -1;
    state->log_next = 1;
    state->log_reset = 0;
    state->last_log_ns = 0;
    state->pps_last_seen = ts_mono.tv_sec;
    state->spurious_pps_count = 0;
    reset_drift(&state->drift);

    return state;
}


enum sync_status poll_exanic_pps_sync(struct exanic_pps_sync_state *state)
{
    struct timespec ts_mono, ts_sys;
    uint32_t pps_reg;
    uint64_t poll_time_ns = 0;
    double drift;
    int drift_known;

    clock_gettime(CLOCK_MONOTONIC, &ts_mono);
    clock_gettime(CLOCK_REALTIME, &ts_sys);

    /* Get clock drift from measurement history */
    drift_known = calc_drift(&state->drift, &drift);

    /* Read the latched timestamp value at the last PPS pulse
     * This must be done before reading the current hardware time */
    pps_reg = exanic_register_read(state->exanic, REG_EXANIC_INDEX(
                REG_EXANIC_PPS_TIMESTAMP));

    /* Get current time from hardware clock */
    if (get_clock_time(state->clkfd, &poll_time_ns) == -1)
    {
        log_printf(LOG_ERR,
                "%s: Error reading time from PTP hardware clock: %s",
                state->name, strerror(errno));
        goto clock_error;
    }

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

    /* Calculate the time of the last PPS pulse */
    if (pps_reg != state->pps_reg)
    {
        uint64_t poll_time_tick, pps_time_tick, desired_time_tick;
        uint32_t poll_time_tick_hi, poll_time_tick_lo;
        uint64_t pps_sys_time_ns;
        double pps_offset;
        time_t time_sec;
        int valid_pps;

        /* Extend the PPS pulse time to 64 bits
         * This calculation assumes the PPS pulse time is before the current
         * hardware time, within one rollover period */
        poll_time_tick = (poll_time_ns / 1000000000) * state->tick_hz +
            (poll_time_ns % 1000000000) * state->tick_hz / 1000000000;
        poll_time_tick_hi = (poll_time_tick >> 32);
        poll_time_tick_lo = (poll_time_tick & 0xFFFFFFFF);
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

        /* Heuristics to reject spurious PPS pulses */
        valid_pps = 0;
        /* If offset small (less than 1ms), assume non-spurious */
        if (fabs(pps_offset) < 1000000)
            valid_pps = 1;
        /* Assume non-spurious for first PPS pulse on startup */
        if (state->pps_time == 0)
            valid_pps = 1;
        /* If too many "spurious" pulses, then we are probably wrong */
        if (state->spurious_pps_count >= SPURIOUS_MAX)
            valid_pps = 1;

        if (!valid_pps)
        {
            state->spurious_pps_count++;
            log_printf(LOG_WARNING, "%s: Ignoring possible spurious PPS, "
                    "clock offset: %.4f us", state->name,
                    pps_offset * 0.001);
        }
        else
        {
            state->spurious_pps_count = 0;

            if ((time_sec - state->pps_time) <= (SKIP_MAX + 1))
            {
                /* Measure drift */
                unsigned seconds = time_sec - state->pps_time;
                double pps_offset_delta = pps_offset - state->pps_offset;
                double error_ppm = pps_offset_delta / (seconds * 1000000000.0);

                /* Record drift measurement */
                record_drift(&state->drift, error_ppm - state->adj, seconds);

                /* Update estimate of clock drift */
                drift_known = calc_drift(&state->drift, &drift);
            }

            state->pps_offset = pps_offset;
            state->pps_time = time_sec;

            if (state->pps_signal != 1)
                log_printf(LOG_INFO, "%s: PPS signal detected",
                        state->name);
            state->pps_signal = 1;
            state->pps_last_seen = ts_mono.tv_sec;

            /* If offset is more than 1us, make sure status is logged */
            if (fabs(state->pps_offset) > 1000)
                state->log_next = 1;

            /* Log measurement */
            if (verbose || state->log_next || state->last_log_ns +
                    LOG_INTERVAL * 1000000000ULL < poll_time_ns)
            {
                log_printf(LOG_INFO, "%s: Clock offset at PPS pulse: %.4f us "
                        " drift: %.4f ppm", state->name,
                        state->pps_offset * 0.001, drift * 1000000);
                state->last_log_ns = poll_time_ns;
            }

            /* Slow down logging if offset is less than 1us */
            if (fabs(state->pps_offset) < 1000)
                state->log_next = 0;
        }

        state->pps_reg = pps_reg;
    }

    /* Check if we haven't seen a PPS pulse for a while */
    if (ts_mono.tv_sec - state->pps_last_seen > TIMEOUT_SECONDS)
    {
        if (state->pps_signal != 0 || state->last_log_ns +
                LOG_INTERVAL * 1000000000ULL < poll_time_ns)
        {
            log_printf(LOG_WARNING, "%s: PPS signal lost",
                    state->name);
            state->last_log_ns = poll_time_ns;
        }

        state->pps_signal = 0;
        state->log_next = 1;
    }

    /* Reset exanic clock if offset is too large (more than 1ms) */
    if (fabs(state->pps_offset) > 1000000)
    {
        uint64_t time_ns;

        if (state->log_reset)
            log_printf(LOG_WARNING, "%s: Clock error exceeds limits, "
                    "resetting clock: %.4f us",
                    state->name, state->pps_offset * 0.001);

        time_ns = poll_time_ns - state->pps_offset;
        if (set_clock_adj(state->clkfd, 0) == -1 ||
                set_clock_time(state->clkfd, time_ns) == -1)
        {
            if (!state->error_mode)
                log_printf(LOG_ERR, "%s: Error resetting clock: %s",
                        state->name, strerror(errno));
            goto clock_error;
        }

        state->pps_offset = 0;
        state->pps_time = 0;
        state->adj = 0;
        state->log_next = 1;
        state->log_reset = 1;
        state->last_log_ns = poll_time_ns;
        state->spurious_pps_count = 0;
        reset_drift(&state->drift);
        return SYNC_OK;
    }

    state->log_reset = 1;

    if (drift_known)
    {
        double offset_correction;
        int64_t time_since_pps_ns;

        /* Measure time since last PPS pulse */
        time_since_pps_ns = poll_time_ns - state->pps_time * 1000000000ULL;
        if (time_since_pps_ns < 10 * PPS_POLL_INTERVAL * 1000000000ULL)
            /* Add offset correction */
            offset_correction = - state->pps_offset /
                (10 * PPS_POLL_INTERVAL * 1000000000LL);
        else
            /* Don't add offset correction, it should be corrected by now */
            offset_correction = 0;

        /* Set adjustment to compensate for drift and to correct offset */
        state->adj = offset_correction - drift;
        if (set_clock_adj(state->clkfd, state->adj) == -1)
        {
            if (!state->error_mode)
                log_printf(LOG_ERR, "%s: Error adjusting clock: %s",
                        state->name, strerror(errno));
            goto clock_error;
        }

        /* If we get here, everything is working correctly */
        if (state->error_mode)
        {
            log_printf(LOG_INFO, "%s: Error state cleared", state->name);
            state->error_mode = 0;
        }
    }

    state->poll_time_ns = poll_time_ns;

    return SYNC_OK;

clock_error:
    state->pps_offset = 0;
    state->pps_time = 0;
    state->adj = 0;
    state->error_mode = 1;
    state->log_next = 1;
    state->log_reset = 1;
    state->last_log_ns = 0;
    state->spurious_pps_count = 0;
    reset_drift(&state->drift);
    return SYNC_FAILED;
}


void shutdown_exanic_pps_sync(struct exanic_pps_sync_state *state)
{
    double drift;

    log_printf(LOG_INFO, "%s: Stopping clock discipline using PPS",
            state->name);

    /* Set adjustment to compensate for drift only */
    calc_drift(&state->drift, &drift);
    set_clock_adj(state->clkfd, -drift);

    exanic_release_handle(state->exanic);

    free(state);
}
