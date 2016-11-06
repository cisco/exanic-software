#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#if HAVE_PTP_CLOCK_H
#include <linux/ptp_clock.h>
#else
#include "ptp_clock_compat.h"
#endif
#include <linux/ethtool.h>
#ifndef ETHTOOL_GET_TS_INFO
#include "ethtool_ts_info.h"
#endif

#include <exanic/exanic.h>
#include <exanic/config.h>

#include "clock-sync/common.h"
#include "clock-sync/phc_sys.h"
#include "clock-sync/exanic_pps.h"
#include "clock-sync/phc_phc.h"
#include "clock-sync/sys_phc.h"

#define SYSLOG_ID "exanic-clock-sync"
#define EXANIC_MAX 16

#define MIN(a, b) ((a) < (b) ? (a) : (b))


static int caught_signal = 0;
static int use_syslog = 0;
static int daemonize = 0;
static char *pidfile = NULL;
static char *prog = NULL;

int verbose = 0;


static void signal_handler(int signum)
{
    caught_signal = signum;
}


void log_printf(int priority, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (use_syslog)
        vsyslog(priority, fmt, ap);
    else
    {
        vprintf(fmt, ap);
        printf("\n");
    }
    va_end(ap);
}


static int get_clockfd(const char *name)
{
    exanic_t *exanic;
    int sockfd, clkfd, ret;
    struct ifreq ifr;
    struct ethtool_ts_info ts_info;
    char phc_device[32];

    /* Try to get PHC device using ETHTOOL_GET_TS_INFO */
    memset(&ts_info, 0, sizeof(ts_info));
    ts_info.cmd = ETHTOOL_GET_TS_INFO;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_data = (void *)&ts_info;
    if ((exanic = exanic_acquire_handle(name)) != NULL)
    {
        /* Provided name is an ExaNIC */
        exanic_get_interface_name(exanic, 0, ifr.ifr_name, IFNAMSIZ);
        exanic_release_handle(exanic);
    }
    else
    {
        /* Provided name is interface name */
        snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    ret = ioctl(sockfd, SIOCETHTOOL, &ifr);
    close(sockfd);
    if (ret == 0)
    {
        /* Open PHC device */
        sprintf(phc_device, "/dev/ptp%d", ts_info.phc_index);
        clkfd = open(phc_device, O_RDWR);
        if (clkfd == -1)
        {
            fprintf(stderr, "%s: %s: %s: %s\n", prog, name,
                    phc_device, strerror(errno));
            return -1;
        }
        return clkfd;
    }

    /* Provided name may be PHC device name */
    snprintf(phc_device, sizeof(phc_device), "/dev/%s", name);
    clkfd = open(phc_device, O_RDWR);
    if (clkfd != -1)
    {
        /* Use ioctl to check if it is a PHC device */
        struct ptp_clock_caps caps;
        if (ioctl(clkfd, PTP_CLOCK_GETCAPS, &caps) == 0)
            return clkfd;
        else
            close(clkfd);
    }

    fprintf(stderr, "%s: %s: Cannot determine device type\n", prog, name);
    return -1;
}


struct exanic_state
{
    char name[32], name_src[32];
    enum {
        SYNC_PHC_SYS, SYNC_EXANIC_PPS, SYNC_PHC_PHC, SYNC_SYS_PHC
    } sync_type;
    enum pps_type pps_type;
    int pps_termination_disable;
    exanic_t *exanic;
    exanic_t *exanic_src;
    int clkfd;
    int clkfd_src;
    int64_t offset;
    struct exanic_pps_sync_state *exanic_pps_sync;
    struct phc_sys_sync_state *phc_sys_sync;
    struct phc_phc_sync_state *phc_phc_sync;
    struct sys_phc_sync_state *sys_phc_sync;
};


int main(int argc, char *argv[])
{
    struct exanic_state s[EXANIC_MAX];
    int fast_poll = 0;
    int using_pps = 0;
    int ret = 0;
    int n = 0;
    int i;
    int pidfd = -1;
    int auto_tai_offset = 1;
    int tai_offset = 0;

    memset(s, 0, sizeof(s));

    prog = argv[0];

    for (i = 1; i < argc; i++)
    {
        if (argv[i][0] == '-')
        {
            /* Option */
            if (strcmp(argv[i], "--daemon") == 0)
                daemonize = 1;
            else if (strcmp(argv[i], "--syslog") == 0)
                use_syslog = 1;
            else if (strcmp(argv[i], "--pidfile") == 0)
            {
                i++;
                if (i >= argc)
                    goto usage_error;
                pidfile = argv[i];
            }
            else if (strcmp(argv[i], "--tai-offset") == 0)
            {
                char *p;
                i++;
                if (i >= argc)
                    goto usage_error;
                tai_offset = strtol(argv[i], &p, 10);
                auto_tai_offset = 0;
                if (p == argv[i] || *p != '\0')
                    goto usage_error;
            }
            else if (strcmp(argv[i], "--verbose") == 0)
                verbose = 1;
            else
                goto usage_error;
        }
        else if (n >= EXANIC_MAX)
        {
            fprintf(stderr, "%s: too many sync targets (max %u)\n", prog, EXANIC_MAX);
            ret = 1;
            goto cleanup;
        }
        else
        {
            char *p, *q;
            char sync_target[16], sync_src[16];
            int64_t offset = 0;
            int require_exanic_target = 0, maybe_exanic_src = 0;
            int require_phc_target = 0, require_phc_src = 0;

            memset(sync_target, 0, sizeof(sync_target));
            memset(sync_src, 0, sizeof(sync_src));

            /* target:source[(+|-)offset] */
            p = strchr(argv[i], ':');
            if (p == NULL || *p != ':')
                goto usage_error;
            strncpy(sync_target, argv[i],
                    MIN(sizeof(sync_target) - 1, p - argv[i]));
            q = p + 1;
            p = strpbrk(q, "+-");
            if (p == NULL)
                p = q + strlen(q);
            strncpy(sync_src, q, MIN(sizeof(sync_src) - 1, p - q));
            if (*p == '+' || *p == '-')
                offset = strtoll(p, &p, 10);
            if (*p != '\0')
                goto usage_error;

            snprintf(s[n].name, sizeof(s[n].name), "%s", sync_target);
            snprintf(s[n].name_src, sizeof(s[n].name_src), "%s", sync_src);

            if (strcmp(sync_target, "sys") == 0 ||
                    strcmp(sync_target, "host") == 0)
            {
                /* Sync system clock from hardware clock */
                s[n].sync_type = SYNC_SYS_PHC;
                maybe_exanic_src = 1;
                require_phc_src = 1;
            }
            else if (strcmp(sync_src, "sys") == 0 || strcmp(sync_src, "host") == 0)
            {
                /* Sync to system clock */
                s[n].sync_type = SYNC_PHC_SYS;
                require_phc_target = 1;
            }
            else if (strcmp(sync_src, "pps") == 0 ||
                    strcmp(sync_src, "pps-single-ended") == 0)
            {
                /* Sync to a PPS signal with termination enabled */
                s[n].sync_type = SYNC_EXANIC_PPS;
                s[n].pps_type = PPS_SINGLE_ENDED;
                require_exanic_target = 1;
                require_phc_target = 1;
                using_pps = 1;
            }
            else if (strcmp(sync_src, "pps-no-term") == 0)
            {
                /* Sync to a PPS signal with termination disabled */
                s[n].sync_type = SYNC_EXANIC_PPS;
                s[n].pps_type = PPS_SINGLE_ENDED;
                s[n].pps_termination_disable = 1;
                require_exanic_target = 1;
                require_phc_target = 1;
                using_pps = 1;
            }
            else if (strcmp(sync_src, "pps-differential") == 0)
            {
                /* Sync to a PPS signal using differential input on ExaNIC X2/X4 */
                s[n].sync_type = SYNC_EXANIC_PPS;
                s[n].pps_type = PPS_DIFFERENTIAL;
                require_exanic_target = 1;
                require_phc_target = 1;
                using_pps = 1;
            }
            else
            {
                /* Sync to another hardware clock */
                s[n].sync_type = SYNC_PHC_PHC;
                require_phc_target = 1;
                require_phc_src = 1;
            }

            s[n].offset = offset;
            s[n].exanic = NULL;
            s[n].exanic_src = NULL;
            s[n].clkfd = -1;
            s[n].clkfd_src = -1;

            if (require_exanic_target)
            {
                if ((s[n].exanic = exanic_acquire_handle(sync_target)) == NULL)
                {
                    fprintf(stderr, "%s: %s: %s\n", prog, sync_target,
                            exanic_get_last_error());
                    ret = 1;
                    goto cleanup;
                }
            }

            if (require_phc_target)
            {
                if ((s[n].clkfd = get_clockfd(sync_target)) == -1)
                {
                    ret = 1;
                    goto cleanup;
                }
            }

            if (maybe_exanic_src)
            {
                /* Not a fatal error if source is not an ExaNIC */
                s[n].exanic_src = exanic_acquire_handle(sync_src);
            }

            if (require_phc_src)
            {
                if ((s[n].clkfd_src = get_clockfd(sync_src)) == -1)
                {
                    fprintf(stderr, "%s: %s: %s\n", prog, sync_src,
                            strerror(errno));
                    ret = 1;
                    goto cleanup;
                }
            }

            n++;
        }
    }

    if (n == 0)
        goto usage_error;

    if (pidfile != NULL)
    {
        /* Create and open PID file */
        if ((pidfd = open(pidfile, O_WRONLY | O_CREAT | O_EXCL, 0644)) == -1)
        {
            fprintf(stderr, "%s: %s: %s\n", prog, pidfile, strerror(errno));
            ret = 1;
            pidfile = NULL;
            goto cleanup;
        }
    }

    if (daemonize)
    {
        pid_t pid;

        if ((pid = fork()) != 0)
        {
            /* Parent process */
            if (pid == -1)
            {
                fprintf(stderr, "%s: fork: %s\n", prog, strerror(errno));
                return 1;
            }
            return 0;
        }

        /* Daemon process */
        setsid();
        stdin = freopen("/dev/null", "r", stdin);
        stdout = freopen("/dev/null", "w", stdout);
        stderr = freopen("/dev/null", "w", stderr);
        signal(SIGHUP, SIG_IGN);
        signal(SIGINT, signal_handler);
        signal(SIGPIPE, SIG_IGN);
        signal(SIGALRM, SIG_IGN);
        signal(SIGTERM, signal_handler);
    }
    else
    {
        signal(SIGHUP, signal_handler);
        signal(SIGINT, signal_handler);
        signal(SIGPIPE, signal_handler);
        signal(SIGALRM, signal_handler);
        signal(SIGTERM, signal_handler);
    }

    if (pidfile != NULL)
    {
        /* Write PID to PID file */
        char buf[16];

        sprintf(buf, "%d\n", getpid());
        if (write(pidfd, buf, strlen(buf)) != strlen(buf))
            /* not much we can do; avoid warning for unchecked return value */ ;
        close(pidfd);
    }

    if (use_syslog)
        openlog(SYSLOG_ID, LOG_PID, LOG_DAEMON);

    /* Initialise state */
    for (i = 0; i < n; i++)
    {
        if (s[i].sync_type == SYNC_PHC_SYS)
            s[i].phc_sys_sync = init_phc_sys_sync(s[i].name, s[i].clkfd,
                    tai_offset, auto_tai_offset, s[i].offset);
        else if (s[i].sync_type == SYNC_EXANIC_PPS)
            s[i].exanic_pps_sync = init_exanic_pps_sync(s[i].name, s[i].clkfd,
                    s[i].exanic, s[i].pps_type, s[i].pps_termination_disable,
                    tai_offset, auto_tai_offset, s[i].offset);
        else if (s[i].sync_type == SYNC_PHC_PHC)
            s[i].phc_phc_sync = init_phc_phc_sync(s[i].name, s[i].clkfd,
                    s[i].name_src, s[i].clkfd_src);
        else if (s[i].sync_type == SYNC_SYS_PHC)
            s[i].sys_phc_sync = init_sys_phc_sync(s[i].name_src,
                    s[i].clkfd_src, s[i].exanic_src,
                    tai_offset, auto_tai_offset, s[i].offset);

        if (s[i].phc_sys_sync == NULL &&
            s[i].exanic_pps_sync == NULL &&
            s[i].phc_phc_sync == NULL &&
            s[i].sys_phc_sync == NULL)
        {
            ret = 1;
            goto cleanup;
        }
    }

    /* Run loop */
    while (1)
    {
        if (fast_poll)
            usleep(SHORT_POLL_INTERVAL * 1000000);
        else if (using_pps)
            usleep(PPS_POLL_INTERVAL * 1000000);
        else
            usleep(POLL_INTERVAL * 1000000);
        fast_poll = 0;

        for (i = 0; i < n; i++)
        {
            enum sync_status stat;

            if (s[i].phc_sys_sync != NULL)
                stat = poll_phc_sys_sync(s[i].phc_sys_sync);
            else if (s[i].exanic_pps_sync != NULL)
                stat = poll_exanic_pps_sync(s[i].exanic_pps_sync);
            else if (s[i].phc_phc_sync != NULL)
                stat = poll_phc_phc_sync(s[i].phc_phc_sync);
            else if (s[i].sys_phc_sync != NULL)
                stat = poll_sys_phc_sync(s[i].sys_phc_sync);
            else
                continue;

            if (stat == SYNC_FAST_POLL)
                fast_poll = 1;
        }

        if (caught_signal != 0)
        {
            log_printf(LOG_INFO, "Caught signal %d, exiting", caught_signal);
            break;
        }
    }

    /* Shutdown */
    for (i = 0; i < n; i++)
    {
        if (s[i].phc_sys_sync != NULL)
            shutdown_phc_sys_sync(s[i].phc_sys_sync);

        if (s[i].exanic_pps_sync != NULL)
            shutdown_exanic_pps_sync(s[i].exanic_pps_sync);

        if (s[i].phc_phc_sync != NULL)
            shutdown_phc_phc_sync(s[i].phc_phc_sync);

        if (s[i].sys_phc_sync != NULL)
            shutdown_sys_phc_sync(s[i].sys_phc_sync);
    }

cleanup:
    for (i = 0; i < n; i++)
    {
        if (s[i].exanic != NULL)
            exanic_release_handle(s[i].exanic);
        if (s[i].clkfd != -1)
            close(s[i].clkfd);
        if (s[i].clkfd_src != -1)
            close(s[i].clkfd_src);
    }

    if (use_syslog)
        closelog();

    if (pidfile != NULL)
        unlink(pidfile);

    return ret;

usage_error:
    fprintf(stderr, "Usage: %s [<options>] <target>:<source>[(+|-)offset] ...\n\n"
            "<target> is an ExaNIC device name or \"sys\" for the system clock\n"
            "<source> is one of:\n"
            "  sys\n"
            "    Sync to system clock\n"
            "  pps\n"
            "    Sync to a PPS signal with default settings (ExaNIC target only)\n"
            "  pps-no-term\n"
            "    Sync to a PPS signal with termination disabled (ExaNIC target only)\n"
            "  pps-differential\n"
            "    Sync to a PPS signal using differential RS-422 input (ExaNIC X2/X4 only)\n"
            "  an ExaNIC device name\n"
            "    Sync to another ExaNIC on this machine\n"
            "<offset> is in nanoseconds\n"
            "<options> are zero or more of:\n"
            "  --daemon\n"
            "    fork the process to operate as a background daemon\n"
            "  --syslog\n"
            "    use syslog to send messages to system logger\n"
            "  --pidfile <filename>\n"
            "    write the PID to provided PID file <filename>\n"
            "  --tai-offset <offset>\n"
            "    manually set the offset between hardware clock time and UTC time\n",
            argv[0]);
    ret = 1;
    goto cleanup;
}
