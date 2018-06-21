/**
 * ExaNIC driver
 * Copyright (C) 2011-2013 Exablaze Pty Ltd and its licensors
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/netdevice.h>
#include <linux/miscdevice.h>
#include <linux/etherdevice.h>

#include "../../libs/exanic/pcie_if.h"
#include "../../libs/exanic/fifo_if.h"
#include "../../libs/exanic/ioctl.h"
#include "exanic.h"
#include "exanic-structs.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
#define PTP_1588_CLOCK_USES_TIMESPEC64
#endif

#if defined(CONFIG_PTP_1588_CLOCK) || defined(CONFIG_PTP_1588_CLOCK_MODULE)

#define PPS_DELAY_NS 100000
#define PER_OUT_DELAY_NS 100000
#define PER_OUT_WIDTH_NS 20000

#define CLK_10M_PERIOD_NS 100
#define CLK_10M_WIDTH_NS 50

/* Log an error if the rollover counter update is out by this many ticks */
#define MAX_ERROR_TICKS 0x1000000

/* How often to update the rollover counter if the time is synced externally */
#define ROLLOVER_UPDATE_TICKS 0x10000000

#ifdef PTP_1588_CLOCK_USES_TIMESPEC64
typedef struct timespec64 ptp_timespec_t;
#define ktime_to_ptp_timespec_t(ktime) ktime_to_timespec64(ktime)
#else
typedef struct timespec ptp_timespec_t;
#define ktime_to_ptp_timespec_t(ktime) ktime_to_timespec(ktime)
#endif

#define EXANIC_SUPPORTS_PER_OUT(exanic) \
    ((exanic)->hw_id == EXANIC_HW_X10 || \
     (exanic)->hw_id == EXANIC_HW_X40 || \
     (exanic)->hw_id == EXANIC_HW_X10_GM || \
     (exanic)->hw_id == EXANIC_HW_X10_HPT) || \
     (exanic)->hw_id == EXANIC_HW_V5P

#define EXANIC_SUPPORTS_PER_OUT_10M(exanic) \
    ((exanic)->hw_id == EXANIC_HW_X10_GM || \
     (exanic)->hw_id == EXANIC_HW_X10_HPT)

static uint64_t exanic_ptp_read_hw_time(struct exanic *exanic);
static uint64_t exanic_ptp_soft_extend_hw_time(struct exanic *exanic,
        uint32_t hw_time);

static void exanic_ptp_update_info_page(struct exanic *exanic)
{
    /* The hw_time field in the info page is at most 1/4 rollover period
     * off from the correct time */
    exanic->info_page->hw_time = (exanic->tick_rollover_counter << 31)
        + 0x40000000;
}

static ktime_t next_rollover_update_time(struct exanic *exanic,
        uint64_t time_ticks)
{
    uint32_t ticks;

    if (exanic->function_id == EXANIC_FUNCTION_PTP_GM)
        /* Timer fires periodically */
        ticks = ROLLOVER_UPDATE_TICKS;
    else
        /* Timer fires when the bottom 31 bits rollover */
        ticks = ((exanic->tick_rollover_counter + 1) << 31) - time_ticks;

    return ns_to_ktime(1000000000ULL * ticks / exanic->tick_hz);
}

/* This timer fires periodically for ExaNIC cards with a 64 bit clock
 * to update the cached upper bits of the time counter */
static enum hrtimer_restart exanic_ptp_hw_hrtimer_callback(struct hrtimer *timer)
{
    struct exanic *exanic =
        container_of(timer, struct exanic, ptp_clock_hrtimer);
    uint64_t time_ticks = exanic_ptp_read_hw_time(exanic);

    if ((time_ticks & 0x7FFFFFFF) > 0x80000000 - MAX_ERROR_TICKS)
        exanic->tick_rollover_counter = (time_ticks >> 31) + 1;
    else
        exanic->tick_rollover_counter = time_ticks >> 31;
    exanic_ptp_update_info_page(exanic);

    hrtimer_forward_now(&exanic->ptp_clock_hrtimer,
            next_rollover_update_time(exanic, time_ticks));

    return HRTIMER_RESTART;
}

/* This timer should fire each half rollover period of the ExaNIC clock
 * on cards which do not have a 64 bit clock
 * Lock is not needed because we stop the timer during critical sections */
static enum hrtimer_restart exanic_ptp_soft_hrtimer_callback(
        struct hrtimer *timer)
{
    struct exanic *exanic =
        container_of(timer, struct exanic, ptp_clock_hrtimer);
    uint32_t hw_time =
        readl(exanic->regs_virt + REG_EXANIC_OFFSET(REG_EXANIC_HW_TIME));
    uint64_t time_ticks = exanic_ptp_soft_extend_hw_time(exanic, hw_time);
    int32_t error;

    if ((exanic->tick_rollover_counter & 1) == 0)
        /* Timer should have fired near halfway point */
        error = hw_time - 0x80000000;
    else
        /* Timer should have fired around rollover time */
        error = hw_time;

    if (error < -MAX_ERROR_TICKS || error > MAX_ERROR_TICKS)
        dev_err(exanic_dev(exanic),
            "Rollover timer fired at an unexpected time: "
            "counter 0x%llx hwtime 0x%08x\n", exanic->tick_rollover_counter,
            hw_time);

    exanic->tick_rollover_counter++;
    exanic_ptp_update_info_page(exanic);

    hrtimer_forward_now(&exanic->ptp_clock_hrtimer,
            next_rollover_update_time(exanic, time_ticks));

    return HRTIMER_RESTART;
}

/* Extend hardware time to 64 bits using tick_rollover_counter */
static uint64_t exanic_ptp_soft_extend_hw_time(struct exanic *exanic,
        uint32_t hw_time)
{
    uint64_t tick_rollover_counter = exanic->tick_rollover_counter;

    /* Get upper 32 bits of timestamp from tick_rollover_counter
     * Lower 32 bits comes from hw_time */
    if (hw_time < 0x40000000 && (tick_rollover_counter & 1) != 0)
        return (((tick_rollover_counter + 1) >> 1) << 32) | hw_time;
    else if (hw_time >= 0xC0000000 && (tick_rollover_counter & 1) == 0)
        return (((tick_rollover_counter - 1) >> 1) << 32) | hw_time;
    else
        return ((tick_rollover_counter >> 1) << 32) | hw_time;
}

/* Read 64 bit hardware time, correcting for rollover */
static uint64_t exanic_ptp_read_hw_time(struct exanic *exanic)
{
    uint32_t hi1, hi2, lo;

    hi1 = readl(exanic->regs_virt + REG_EXANIC_OFFSET(REG_EXANIC_HW_TIME_HI));
    lo = readl(exanic->regs_virt + REG_EXANIC_OFFSET(REG_EXANIC_HW_TIME));
    hi2 = readl(exanic->regs_virt + REG_EXANIC_OFFSET(REG_EXANIC_HW_TIME_HI));

    if (hi1 == hi2)
        return ((uint64_t)hi1) << 32 | lo;
    else if (lo < 0x80000000)
        return ((uint64_t)hi2) << 32 | lo;
    else
        return ((uint64_t)hi1) << 32 | lo;
}

/* Extend hardware time to 64 bits and translate to ktime_t */
ktime_t exanic_ptp_time_to_ktime(struct exanic *exanic, uint32_t hw_time)
{
    uint32_t tick_hz = exanic->tick_hz;
    uint64_t time_ticks;

    if (exanic->caps & EXANIC_CAP_HW_TIME_HI)
    {
        time_ticks = exanic_ptp_read_hw_time(exanic);
        if (hw_time < 0x40000000 && (time_ticks & 0x80000000) != 0)
            time_ticks = (((time_ticks >> 32) + 1) << 32) | hw_time;
        else if (hw_time >= 0xC0000000 && (time_ticks & 0x80000000) == 0)
            time_ticks = (((time_ticks >> 32) - 1) << 32) | hw_time;
        else
            time_ticks = ((time_ticks >> 32) << 32) | hw_time;
    }
    else
        time_ticks = exanic_ptp_soft_extend_hw_time(exanic, hw_time);

    return ktime_set(time_ticks / tick_hz,
            (time_ticks % tick_hz) * 1000000000 / tick_hz);
}

/* Get current hardware time as ktime_t */
static ktime_t exanic_ptp_ktime_get(struct exanic *exanic)
{
    uint32_t tick_hz = exanic->tick_hz;
    uint32_t hw_time_reg;
    uint64_t time_ticks;

    if (exanic->caps & EXANIC_CAP_HW_TIME_HI)
        time_ticks = exanic_ptp_read_hw_time(exanic);
    else
    {
        hw_time_reg = readl(exanic->regs_virt +
                REG_EXANIC_OFFSET(REG_EXANIC_HW_TIME));
        time_ticks = exanic_ptp_soft_extend_hw_time(exanic, hw_time_reg);
    }

    return ktime_set(time_ticks / tick_hz,
            (time_ticks % tick_hz) * 1000000000 / tick_hz);
}

/* Return an expiry time for the next second boundary */
static ktime_t next_pps_time(struct exanic *exanic)
{
    ktime_t time_hw, time_mono;
    unsigned long ns;

    /* Get hardware time and monotonic time */
    time_hw = exanic_ptp_ktime_get(exanic);
    time_mono = ktime_get();

    /* Calculate time until next second boundary */
    ns = NSEC_PER_SEC - ktime_to_timespec(time_hw).tv_nsec + PPS_DELAY_NS;

    return ktime_add_ns(time_mono, ns);
}

/* This timer fires close to each second boundary
 * It is used to trigger PPS events for system time synchronization */
static enum hrtimer_restart exanic_ptp_pps_hrtimer_callback(
        struct hrtimer *timer)
{
    struct exanic *exanic =
        container_of(timer, struct exanic, phc_pps_hrtimer);
    struct device *dev = &exanic->pci_dev->dev;
    struct ptp_clock_event event;
    unsigned long flags;
    ktime_t hw_time, mono_time;
    uint32_t hw_time_reg;
    struct timespec hw_time_ts;
    uint64_t expiry;

    if (!exanic->phc_pps_enabled)
        return HRTIMER_NORESTART;

    memset(&event, 0, sizeof(event));
    event.type = PTP_CLOCK_PPSUSR;

    /* Disable interrupts to avoid random delays when reading time */
    local_irq_save(flags);

    /* Get hardware time, system time and monotonic time */
    hw_time_reg = readl(exanic->regs_virt + REG_EXANIC_OFFSET(REG_EXANIC_HW_TIME));
    pps_get_ts(&event.pps_times);
    mono_time = ktime_get();

    local_irq_restore(flags);

    hw_time = exanic_ptp_time_to_ktime(exanic, hw_time_reg);
    hw_time_ts = ktime_to_timespec(hw_time);

    /* Get the system time at the last second boundary */
    pps_sub_ts(&event.pps_times, ns_to_timespec(hw_time_ts.tv_nsec));

    /* Set next expiry to be just after the next second boundary */
    expiry = NSEC_PER_SEC - hw_time_ts.tv_nsec + PPS_DELAY_NS;

    if (hw_time_ts.tv_nsec < 5 * NSEC_PER_MSEC)
    {
        /* Trigger PPS event only within 5ms of second boundary */
        ptp_clock_event(exanic->ptp_clock, &event);
    }
    else
    {
        /* Timer may have fired too late or too early */
        if (exanic->last_phc_pps != 0 &&
                exanic->last_phc_pps < hw_time_ts.tv_sec)
            dev_err(dev, "Missed PPS event at time=%ld delay=%ld\n",
                    hw_time_ts.tv_sec, hw_time_ts.tv_nsec);

        /* Monotonic clock may be too fast or slow, so use a short timeout to
         * ensure the next second boundary is not missed */
        if (expiry > 50 * NSEC_PER_MSEC)
            expiry = 50 * NSEC_PER_MSEC;
    }

    exanic->last_phc_pps = hw_time_ts.tv_sec;

    hrtimer_set_expires(&exanic->phc_pps_hrtimer,
            ktime_add_ns(mono_time, expiry));

    return HRTIMER_RESTART;
}

static void exanic_ptp_per_out_update(struct exanic *exanic)
{
    ktime_t time_hw;
    ptp_timespec_t ts;
    uint64_t ticks, n;
    uint32_t width;
    ktime_t time_next = ns_to_ktime(0);
    uint32_t width_ns = 0;
    uint32_t config = 0;

    /* Current hardware time with a small delay added */
    time_hw = ktime_add_ns(exanic_ptp_ktime_get(exanic), PER_OUT_DELAY_NS);

    if (exanic->per_out_mode == PER_OUT_1PPS)
    {
        if (ktime_to_ns(ktime_sub(exanic->per_out_start, time_hw)) < 0)
        {
            /* Advance periodic output start time to after current time */
            n = ktime_divns(ktime_sub(time_hw, exanic->per_out_start),
                    NSEC_PER_SEC);
            time_next = ktime_add_ns(exanic->per_out_start,
                    NSEC_PER_SEC * (n + 1));
        }
        else
        {
            /* Set periodic output start time to be no more than output period
             * after current time */
            n = ktime_divns(ktime_sub(exanic->per_out_start, time_hw),
                    NSEC_PER_SEC);
            time_next = ktime_sub_ns(exanic->per_out_start, NSEC_PER_SEC * n);
        }

        width_ns = PER_OUT_WIDTH_NS;
        config = EXANIC_HW_PER_OUT_CONFIG_PPS;
    }
    else if (exanic->per_out_mode == PER_OUT_10M)
    {
        /* The provided start time is ignored in this mode.
         * Start time is next 100ns boundary after current time */
        n = ktime_divns(time_hw, CLK_10M_PERIOD_NS);
        time_next = ns_to_ktime((n + 1) * CLK_10M_PERIOD_NS);
        width_ns = CLK_10M_WIDTH_NS;
        config = EXANIC_HW_PER_OUT_CONFIG_10M;
    }

    /* Calculate next output time in ticks */
    ts = ktime_to_ptp_timespec_t(time_next);
    ticks = (ts.tv_sec * exanic->tick_hz) +
        ((uint64_t)ts.tv_nsec * exanic->tick_hz / NSEC_PER_SEC);

    /* Output pulse width in ticks */
    width = (uint64_t)width_ns * exanic->tick_hz / NSEC_PER_SEC;

    /* Program the hardware */
    writel(width, exanic->regs_virt + REG_HW_OFFSET(REG_HW_PER_OUT_WIDTH));
    writel(config, exanic->regs_virt + REG_HW_OFFSET(REG_HW_PER_OUT_CONFIG));
    writel(ticks & 0xFFFFFFFF,
            exanic->regs_virt + REG_HW_OFFSET(REG_HW_NEXT_PER_OUT));
}

/* Clock adjustment is not allowed if GPS sync is enabled */
static bool exanic_ptp_adj_allowed(struct exanic *exanic)
{
    uint32_t conf0;

    if (exanic->function_id == EXANIC_FUNCTION_PTP_GM)
    {
        conf0 = readl(exanic->regs_virt + REG_PTP_OFFSET(REG_PTP_CONF0));
        if (conf0 & EXANIC_PTP_CONF0_GPS_CLOCK_SYNC)
            return false;
    }

    return true;
}

static int exanic_phc_adjfreq(struct ptp_clock_info *ptp, s32 delta)
{
    struct exanic *exanic = container_of(ptp, struct exanic, ptp_clock_info);
    uint32_t reg;

    if (!exanic_ptp_adj_allowed(exanic))
        return -EOPNOTSUPP;

    /* delta is desired frequency offset from nominal in ppb */

    if (exanic->caps & EXANIC_CAP_CLK_ADJ_EXT)
    {
        /* Use extended clock correction register
         * Convert from parts per billion to parts per 2^40 */
        reg = (int32_t)(((int64_t)delta << 31) / 1953125);

        writel(reg, exanic->regs_virt +
                REG_EXANIC_OFFSET(REG_EXANIC_CLK_ADJ_EXT));
    }
    else
    {
        if (delta > 0)
            reg = EXANIC_CLK_ADJ_INC |
                  ((1000000000 / delta) & EXANIC_CLK_ADJ_MASK);
        else if (delta < 0)
            reg = EXANIC_CLK_ADJ_DEC |
                  ((1000000000 / -delta) & EXANIC_CLK_ADJ_MASK);
        else
            reg = 0;
        writel(reg, exanic->regs_virt + REG_EXANIC_OFFSET(REG_EXANIC_CLK_ADJ));
    }

    return 0;
}

/* Common code for exanic_phc_adjtime and exanic_phc_settime */
static int exanic_phc_adjtime_common(struct ptp_clock_info *ptp,
                                     const ptp_timespec_t *ts, s64 delta)
{
    struct exanic *exanic = container_of(ptp, struct exanic, ptp_clock_info);
    uint64_t time_ticks;
    unsigned long flags;

    if (!exanic_ptp_adj_allowed(exanic))
        return -EOPNOTSUPP;

    /* Lock to prevent someone else adjusting the clock at the same time */
    spin_lock_irqsave(&exanic->ptp_clock_lock, flags);

    /* Prevent timers from firing while we are changing the counter value */
    hrtimer_cancel(&exanic->ptp_clock_hrtimer);
    if (exanic->phc_pps_enabled)
        hrtimer_cancel(&exanic->phc_pps_hrtimer);

    if (ts == NULL)
    {
        /* Adjust time by offset */
        int64_t delta_ticks = (delta / 1000000000 * exanic->tick_hz) +
            ((delta % 1000000000) * exanic->tick_hz / 1000000000);

        if (exanic->caps & EXANIC_CAP_HW_TIME_HI)
            time_ticks = exanic_ptp_read_hw_time(exanic);
        else
            time_ticks = exanic_ptp_soft_extend_hw_time(exanic,
                    readl(exanic->regs_virt +
                        REG_EXANIC_OFFSET(REG_EXANIC_HW_TIME)));

        time_ticks += delta_ticks;
    }
    else
    {
        /* Set absolute time */
        time_ticks = (ts->tv_sec * exanic->tick_hz) +
            ((uint64_t)ts->tv_nsec * exanic->tick_hz / 1000000000);
    }

    if (exanic->caps & EXANIC_CAP_HW_TIME_HI)
    {
        /* Write upper bits of the counter. The time is not updated until
         * the lower bits are written */
        writel(time_ticks >> 32,
                exanic->regs_virt + REG_EXANIC_OFFSET(REG_EXANIC_CLK_SET_HI));
    }

    /* Write lower 32 bits of the counter */
    writel(time_ticks & 0xFFFFFFFF,
            exanic->regs_virt + REG_EXANIC_OFFSET(REG_EXANIC_CLK_SET));

    /* Keep track of upper bits in software */
    exanic->tick_rollover_counter = time_ticks >> 31;
    exanic_ptp_update_info_page(exanic);

    /* Set timer to fire when the upper bits change */
    hrtimer_start(&exanic->ptp_clock_hrtimer,
            next_rollover_update_time(exanic, time_ticks),
            HRTIMER_MODE_REL);

    /* Update periodic output settings */
    if (exanic->per_out_mode != PER_OUT_NONE)
        exanic_ptp_per_out_update(exanic);

    if (exanic->phc_pps_enabled)
    {
        /* Set PPS timer to fire at the next second boundary */
        exanic->last_phc_pps = 0;
        hrtimer_start(&exanic->phc_pps_hrtimer, next_pps_time(exanic),
                      HRTIMER_MODE_ABS);
    }

    spin_unlock_irqrestore(&exanic->ptp_clock_lock, flags);

    return 0;
}

static int exanic_phc_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
    return exanic_phc_adjtime_common(ptp, NULL, delta);
}

static int exanic_phc_gettime(struct ptp_clock_info *ptp,
                              ptp_timespec_t *ts)
{
    struct exanic *exanic = container_of(ptp, struct exanic, ptp_clock_info);

    *ts = ktime_to_ptp_timespec_t(exanic_ptp_ktime_get(exanic));

    return 0;
}

static int exanic_phc_settime(struct ptp_clock_info *ptp,
                              const ptp_timespec_t *ts)
{
    return exanic_phc_adjtime_common(ptp, ts, 0);
}

static int exanic_phc_enable(struct ptp_clock_info *ptp,
                             struct ptp_clock_request *request,
                             int on)
{
    struct exanic *exanic = container_of(ptp, struct exanic, ptp_clock_info);
    struct device *dev = &exanic->pci_dev->dev;
    unsigned long flags;
    uint32_t reg;
    enum per_out_mode per_out_mode;

    switch (request->type)
    {
    case PTP_CLK_REQ_PPS:
        spin_lock_irqsave(&exanic->ptp_clock_lock, flags);
        if (on)
        {
            exanic->last_phc_pps = 0;
            exanic->phc_pps_enabled = true;
            hrtimer_start(&exanic->phc_pps_hrtimer, next_pps_time(exanic),
                          HRTIMER_MODE_ABS);
            dev_info(dev, "PTP hardware clock PPS enabled");
        }
        else
        {
            exanic->last_phc_pps = 0;
            exanic->phc_pps_enabled = false;
            hrtimer_cancel(&exanic->phc_pps_hrtimer);
            dev_info(dev, "PTP hardware clock PPS disabled");
        }
        spin_unlock_irqrestore(&exanic->ptp_clock_lock, flags);
        return 0;

    case PTP_CLK_REQ_PEROUT:
        if (request->perout.index >= exanic->ptp_clock_info.n_per_out)
            return -EINVAL;

        if (on)
        {
            /* Only allow period of 1s or 100ns */
            uint64_t period_ns = request->perout.period.nsec +
                request->perout.period.sec * NSEC_PER_SEC;
            if (period_ns == NSEC_PER_SEC)
                per_out_mode = PER_OUT_1PPS;
            else if (period_ns == 100)
                per_out_mode = PER_OUT_10M;
            else
                return -EINVAL;

            /* 100ns period is only supported on X10-GM/X10-HPT */
            if (per_out_mode == PER_OUT_10M &&
                    !EXANIC_SUPPORTS_PER_OUT_10M(exanic))
                return -EINVAL;
        }

        spin_lock_irqsave(&exanic->ptp_clock_lock, flags);
        if (on)
        {
            /* Configure periodic output settings */
            exanic->per_out_mode = per_out_mode;
            exanic->per_out_start = ktime_set(request->perout.start.sec,
                    request->perout.start.nsec);

            /* Enable periodic output */
            exanic_ptp_per_out_update(exanic);
            reg = readl(exanic->regs_virt + REG_HW_OFFSET(REG_HW_SERIAL_PPS));
            reg |= EXANIC_HW_SERIAL_PPS_OUT_EN;
            writel(reg, exanic->regs_virt + REG_HW_OFFSET(REG_HW_SERIAL_PPS));

            dev_info(dev, "PTP hardware clock periodic output enabled");
        }
        else
        {
            /* Disable periodic output */
            exanic->per_out_mode = PER_OUT_NONE;
            reg = readl(exanic->regs_virt + REG_HW_OFFSET(REG_HW_SERIAL_PPS));
            reg &= ~EXANIC_HW_SERIAL_PPS_OUT_EN;
            writel(reg, exanic->regs_virt + REG_HW_OFFSET(REG_HW_SERIAL_PPS));
            writel(0, exanic->regs_virt + REG_HW_OFFSET(REG_HW_PER_OUT_WIDTH));
            writel(0, exanic->regs_virt + REG_HW_OFFSET(REG_HW_PER_OUT_CONFIG));

            dev_info(dev, "PTP hardware clock periodic output disabled");
        }
        spin_unlock_irqrestore(&exanic->ptp_clock_lock, flags);
        return 0;

    default:
        return -EOPNOTSUPP;
    }
}

static const struct ptp_clock_info exanic_ptp_clock_info = {
    .owner      = THIS_MODULE,
    .pps        = 1,
    .adjfreq    = exanic_phc_adjfreq,
    .adjtime    = exanic_phc_adjtime,
#ifdef PTP_1588_CLOCK_USES_TIMESPEC64
    .gettime64  = exanic_phc_gettime,
    .settime64  = exanic_phc_settime,
#else
    .gettime    = exanic_phc_gettime,
    .settime    = exanic_phc_settime,
#endif
    .enable     = exanic_phc_enable,
};

void exanic_ptp_init(struct exanic *exanic)
{
    struct device *dev = &exanic->pci_dev->dev;
    uint32_t reg;
    uint64_t time_ticks;

    exanic->tick_hz =
        readl(exanic->regs_virt + REG_EXANIC_OFFSET(REG_EXANIC_CLK_HZ));
    if (exanic->tick_hz == 0)
    {
        exanic->ptp_clock = NULL;
        dev_err(dev, "Invalid clock frequency");
        return;
    }

    exanic->ptp_clock_info = exanic_ptp_clock_info;
    snprintf(exanic->ptp_clock_info.name, sizeof(exanic->ptp_clock_info.name),
            "%s", exanic->name);
    /* Maximum allowed adjustment in parts per billion */
    if (exanic->caps & EXANIC_CAP_CLK_ADJ_EXT)
        /* Adjustment represented by maximum value of the adjustment register */
        exanic->ptp_clock_info.max_adj = 1953124;
    else
        exanic->ptp_clock_info.max_adj = 100000000;
    /* Periodic output is only available on X10/X40/X10-GM/X10-HPT */
    if (EXANIC_SUPPORTS_PER_OUT(exanic))
        exanic->ptp_clock_info.n_per_out = 1;
    else
        exanic->ptp_clock_info.n_per_out = 0;

    hrtimer_init(&exanic->ptp_clock_hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    if (exanic->caps & EXANIC_CAP_HW_TIME_HI)
        exanic->ptp_clock_hrtimer.function = &exanic_ptp_hw_hrtimer_callback;
    else
        exanic->ptp_clock_hrtimer.function = &exanic_ptp_soft_hrtimer_callback;

    hrtimer_init(&exanic->phc_pps_hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
    exanic->phc_pps_hrtimer.function = &exanic_ptp_pps_hrtimer_callback;

    spin_lock_init(&exanic->ptp_clock_lock);

    exanic->ptp_clock = ptp_clock_register(&exanic->ptp_clock_info, dev);
    if (IS_ERR(exanic->ptp_clock))
    {
        exanic->ptp_clock = NULL;
        dev_err(dev, "Failed to register PTP hardware clock");
        return;
    }

    dev_info(dev, "PTP hardware clock registered (ptp%i)",
            ptp_clock_index(exanic->ptp_clock));

    if (EXANIC_SUPPORTS_PER_OUT(exanic))
    {
        if ((exanic)->hw_id == EXANIC_HW_X10_GM)
        {
            /* Read persisted values from ExaNIC GM  */
            reg = readl(exanic->regs_virt + REG_HW_OFFSET(REG_HW_PER_OUT_CONFIG));
            if (reg & EXANIC_HW_PER_OUT_CONFIG_PPS)
                exanic->per_out_mode = PER_OUT_1PPS;
            else if (reg & EXANIC_HW_PER_OUT_CONFIG_10M)
                exanic->per_out_mode = PER_OUT_10M;
            else
                exanic->per_out_mode = PER_OUT_NONE;
        }
        else
        {
            /* Disable periodic output */
            writel(0, exanic->regs_virt + REG_HW_OFFSET(REG_HW_PER_OUT_WIDTH));
            writel(0, exanic->regs_virt + REG_HW_OFFSET(REG_HW_PER_OUT_CONFIG));
        }
    }

    if (exanic_ptp_adj_allowed(exanic))
    {
        /* Reset the hardware clock */
        dev_info(dev, "Resetting PTP hardware clock");
        if (exanic->caps & EXANIC_CAP_HW_TIME_HI)
            writel(0, exanic->regs_virt +
                    REG_EXANIC_OFFSET(REG_EXANIC_CLK_SET_HI));
        writel(0, exanic->regs_virt + REG_EXANIC_OFFSET(REG_EXANIC_CLK_SET));
        writel(0, exanic->regs_virt + REG_EXANIC_OFFSET(REG_EXANIC_CLK_ADJ));
        time_ticks = 0;
        exanic->tick_rollover_counter = 0;
    }
    else
    {
        /* Get time from hardware clock */
        time_ticks = exanic_ptp_read_hw_time(exanic);
        exanic->tick_rollover_counter = time_ticks >> 31;
    }

    exanic_ptp_update_info_page(exanic);

    /* Set timer to fire when the upper bits change */
    hrtimer_start(&exanic->ptp_clock_hrtimer,
            next_rollover_update_time(exanic, time_ticks),
            HRTIMER_MODE_REL);

    /* PPS events are disabled on init */
    exanic->last_phc_pps = 0;
    exanic->phc_pps_enabled = false;
}

void exanic_ptp_remove(struct exanic *exanic)
{
    struct device *dev = &exanic->pci_dev->dev;

    if (exanic->ptp_clock == NULL)
        return;
    hrtimer_cancel(&exanic->ptp_clock_hrtimer);
    hrtimer_cancel(&exanic->phc_pps_hrtimer);
    ptp_clock_unregister(exanic->ptp_clock);
    exanic->ptp_clock = NULL;
    dev_info(dev, "PTP hardware clock removed");
}

#else

ktime_t exanic_ptp_time_to_ktime(struct exanic *exanic, uint32_t hw_time)
{
    return ns_to_ktime(0);
}

#endif
