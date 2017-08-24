#include <time.h>
#include <stdio.h>
#include <ctype.h>
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
#define NAME_LEN 32

/* Clock rate averaging interval in seconds, only applicable for PPS */
#define DEFAULT_INTERVAL 4

#define MIN(a, b) ((a) < (b) ? (a) : (b))


static int caught_signal = 0;
static int use_syslog = 0;
static int daemonize = 0;
static int auto_tai_offset = 1;
static int tai_offset = 0;
static char *pidfile = NULL;
static char *conffile = NULL;
static char *prog = NULL;

int verbose = 0;

struct exanic_state
{
    char name[NAME_LEN], name_src[NAME_LEN];
    enum {
        SYNC_INVALID, SYNC_PHC_SYS, SYNC_EXANIC_PPS, SYNC_PHC_PHC, SYNC_SYS_PHC
    } sync_type;
    enum pps_type pps_type;
    int pps_termination_disable;
    int64_t offset;
    unsigned interval;
    exanic_t *exanic;
    exanic_t *exanic_src;
    int clkfd;
    int clkfd_src;
    struct exanic_pps_sync_state *exanic_pps_sync;
    struct phc_sys_sync_state *phc_sys_sync;
    struct phc_phc_sync_state *phc_phc_sync;
    struct sys_phc_sync_state *sys_phc_sync;
};

static struct exanic_state s[EXANIC_MAX];
static int n = 0;


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
        fflush(stdout);
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


static void trim_copy(char *dst, char *p, char *q)
{
    while (p < q && isspace(*p))
        p++;
    while (p < q && isspace(*(q - 1)))
        q--;
    memcpy(dst, p, q - p);
    dst[q - p] = '\0';
}


static int parse_bool(char *str)
{
    if (strlen(str) == 0 || strcasecmp(str, "false") == 0 ||
            strcasecmp(str, "no") == 0 || strcasecmp(str, "off") == 0)
        return 0;
    else if (!isdigit(str[0]))
        return 1;
    else
        return strtol(str, NULL, 10) != 0;
}


static int parse_cmdline(int argc, char *argv[])
{
    int i;

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
            else if (strcmp(argv[i], "--config") == 0)
            {
                i++;
                if (i >= argc)
                    goto usage_error;
                conffile = argv[i];
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
            return 1;
        }
        else
        {
            char *p, *q, *r;
            char sync_target[NAME_LEN], sync_src[NAME_LEN + 32];
            int64_t offset = 0;

            memset(sync_target, 0, sizeof(sync_target));
            memset(sync_src, 0, sizeof(sync_src));

            /* target:source[(+|-)offset] */
            p = strchr(argv[i], ':');
            if (p == NULL || *p != ':')
                goto usage_error;
            strncpy(sync_target, argv[i],
                    MIN(sizeof(sync_target) - 1, p - argv[i]));
            q = p + 1;
            r = q;
            while (*r != '\0')
            {
                p = strpbrk(r, "+-");
                if (p == NULL)
                    break;
                r = p + 1;
                if (*r >= '0' && *r <= '9')
                    break;
            }
            if (*r == '\0')
                goto usage_error;
            if (p == NULL)
                p = q + strlen(q);
            strncpy(sync_src, q, MIN(sizeof(sync_src) - 1, p - q));
            if (*p == '+' || *p == '-')
                offset = strtoll(p, &p, 10);
            if (*p != '\0')
                goto usage_error;

            snprintf(s[n].name, sizeof(s[n].name), "%s", sync_target);
            snprintf(s[n].name_src, sizeof(s[n].name_src), "%s", sync_src);

            s[n].sync_type = SYNC_INVALID;
            s[n].pps_type = PPS_SINGLE_ENDED;
            s[n].pps_termination_disable = 0;
            s[n].offset = offset;
            s[n].interval = DEFAULT_INTERVAL;
            s[n].exanic = NULL;
            s[n].exanic_src = NULL;
            s[n].clkfd = -1;
            s[n].clkfd_src = -1;

            n++;
        }
    }

    if (n == 0 && conffile == NULL)
        goto usage_error;

    return 0;

usage_error:
    fprintf(stderr,
            "Usage: %s [<options>] <target>:<source>[(+|-)offset] ...\n"
            "       %s [<options>] --config <conffile>\n\n"
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
            "    manually set the offset between hardware clock time and UTC time\n"
            "  --config <conffile>\n"
            "    path to config file with clock sync settings\n",
            argv[0], argv[0]);
    return 1;
}


static int parse_config(char *filename)
{
    FILE *f = NULL;
    char line[256], section[256], key[256], value[256];
    char *p, *q, *r;
    int m = n;
    int c = -1;
    int ret = 0;
    int linenum = 0;

    f = fopen(filename, "r");
    if (f == NULL)
    {
        fprintf(stderr, "%s: %s: %s\n", prog, filename, strerror(errno));
        ret = 1;
        goto cleanup;
    }

    strcpy(section, "");

    while (fgets(line, sizeof(line), f) != NULL)
    {
        linenum++;
        p = line;
        q = line + strlen(line);

        /* Trim leading and trailing whitespace characters */
        while (isspace(*p))
            p++;
        while (p < q && isspace(*(q - 1)))
            q--;
        /* Skip blank lines and comment lines */
        if (p >= q || *p == ';' || *p == '#')
            continue;

        if (*p == '[')
        {
            /* Section name */
            if (q - 1 < p + 1 || *(q - 1) != ']')
                goto parse_error;
            trim_copy(section, p + 1, q - 1);

            /* Look for sync target that matches the section name */
            for (c = m; c < n; c++)
            {
                if (strncmp(section, s[c].name, NAME_LEN - 1) == 0)
                    break;
            }
            if (c < n)
                continue;

            /* Allocate a new sync target */
            if (n >= EXANIC_MAX)
            {
                fprintf(stderr, "%s: too many sync targets (max %u)\n",
                        prog, EXANIC_MAX);
                ret = 1;
                goto cleanup;
            }

            snprintf(s[n].name, NAME_LEN, "%s", section);
            memset(s[n].name_src, 0, NAME_LEN);

            s[n].sync_type = SYNC_INVALID;
            s[n].pps_type = PPS_SINGLE_ENDED;
            s[n].pps_termination_disable = 0;
            s[n].offset = 0;
            s[n].interval = DEFAULT_INTERVAL;
            s[n].exanic = NULL;
            s[n].exanic_src = NULL;
            s[n].clkfd = -1;
            s[n].clkfd_src = -1;
            c = n;
            n++;
            continue;
        }

        /* Parse as key-value pair */
        r = p;
        while (r + 1 < q && *r != '=')
            r++;
        if (*r != '=')
            goto parse_error;
        trim_copy(key, p, r);
        trim_copy(value, r + 1, q);

        if (c != -1)
        {
            if (strcmp(key, "source") == 0)
            {
                snprintf(s[c].name_src, sizeof(s[c].name_src), "%s", value);
            }
            else if (strcmp(key, "pps_termination") == 0 ||
                    strcmp(key, "pps_term") == 0)
            {
                s[c].pps_termination_disable = !parse_bool(value);
            }
            else if (strcmp(key, "offset") == 0)
            {
                char *e;
                long long offset = strtoll(value, &e, 10);
                if (*e != '\0')
                    goto parse_error;
                s[c].offset = offset;
            }
            else if (strcmp(key, "interval") == 0)
            {
                char *e;
                long interval = strtol(value, &e, 10);
                if (*e != '\0')
                    goto parse_error;
                if (interval < 0)
                {
                    fprintf(stderr, "%s: %s:%d: interval cannot be negative\n",
                            prog, filename, linenum);
                    ret = 1;
                    goto cleanup;
                }
                s[c].interval = interval;
            }
            else
            {
                fprintf(stderr, "%s: %s:%d: unknown option: %s\n",
                        prog, filename, linenum, key);
                ret = 1;
                goto cleanup;
            }
        }
    }

cleanup:
    fclose(f);
    return ret;

parse_error:
    p = line + strlen(line) - 1;
    while (p > line && *p == '\n')
        *(p--) = '\0';
    fprintf(stderr, "%s: %s:%d: parse error: %s\n", prog, filename,
            linenum, line);
    ret = 1;
    goto cleanup;
}


int main(int argc, char *argv[])
{
    int fast_poll = 0;
    int using_pps = 0;
    int ret = 0;
    int i;
    int pidfd = -1;
    int sys_synced = 0;

    prog = argv[0];

    ret = parse_cmdline(argc, argv);
    if (ret != 0)
        goto cleanup;

    if (conffile != NULL)
    {
        ret = parse_config(conffile);
        if (ret != 0)
            goto cleanup;
    }

    if (n == 0)
    {
        fprintf(stderr, "%s: no clocks to synchronize\n", prog);
        ret = 1;
        goto cleanup;
    }

    /* Determine sync type, then acquire ExaNIC handles and PHC clocks */
    for (i = 0; i < n; i++)
    {
        if (strcmp(s[i].name, "sys") == 0 || strcmp(s[i].name, "host") == 0)
        {
            /* Sync system clock from hardware clock */
            s[i].sync_type = SYNC_SYS_PHC;
        }
        else if (strcmp(s[i].name_src, "sys") == 0 ||
                strcmp(s[i].name_src, "host") == 0)
        {
            /* Sync to system clock */
            s[i].sync_type = SYNC_PHC_SYS;
        }
        else if (strcmp(s[i].name_src, "pps") == 0 ||
                strcmp(s[i].name_src, "pps-single-ended") == 0)
        {
            /* Sync to a PPS signal with termination enabled */
            s[i].sync_type = SYNC_EXANIC_PPS;
            s[i].pps_type = PPS_SINGLE_ENDED;
            using_pps = 1;
        }
        else if (strcmp(s[i].name_src, "pps-no-term") == 0)
        {
            /* Sync to a PPS signal with termination disabled */
            s[i].sync_type = SYNC_EXANIC_PPS;
            s[i].pps_type = PPS_SINGLE_ENDED;
            s[i].pps_termination_disable = 1;
            using_pps = 1;
        }
        else if (strcmp(s[i].name_src, "pps-differential") == 0)
        {
            /* Sync to a PPS signal using differential input on ExaNIC X2/X4 */
            s[i].sync_type = SYNC_EXANIC_PPS;
            s[i].pps_type = PPS_DIFFERENTIAL;
            using_pps = 1;
        }
        else
        {
            /* Sync to another hardware clock */
            s[i].sync_type = SYNC_PHC_PHC;
        }

        if (s[i].sync_type == SYNC_EXANIC_PPS)
        {
            /* Target must be an ExaNIC hardware clock */
            if ((s[i].exanic = exanic_acquire_handle(s[i].name)) == NULL)
            {
                fprintf(stderr, "%s: %s: %s\n", prog, s[i].name,
                        exanic_get_last_error());
                ret = 1;
                goto cleanup;
            }
        }
        else if (s[i].sync_type == SYNC_PHC_PHC ||
                 s[i].sync_type == SYNC_PHC_SYS)
        {
            /* Target may be an ExaNIC hardware clock */
            s[i].exanic = exanic_acquire_handle(s[i].name);
        }

        if (s[i].sync_type == SYNC_EXANIC_PPS ||
            s[i].sync_type == SYNC_PHC_PHC ||
            s[i].sync_type == SYNC_PHC_SYS)
        {
            /* Target must be a hardware clock */
            if ((s[i].clkfd = get_clockfd(s[i].name)) == -1)
            {
                ret = 1;
                goto cleanup;
            }
        }

        if (s[i].sync_type == SYNC_PHC_PHC ||
            s[i].sync_type == SYNC_SYS_PHC)
        {
            /* Source may be an ExaNIC hardware clock */
            s[i].exanic_src = exanic_acquire_handle(s[i].name_src);
        }

        if (s[i].sync_type == SYNC_PHC_PHC ||
            s[i].sync_type == SYNC_SYS_PHC)
        {
            /* Source must be a hardware clock */
            if ((s[i].clkfd_src = get_clockfd(s[i].name_src)) == -1)
            {
                fprintf(stderr, "%s: %s: %s\n", prog, s[i].name_src,
                        strerror(errno));
                ret = 1;
                goto cleanup;
            }
        }
    }

    /* Record which clocks we are synchronizing and check for conflicts */
    for (i = 0; i < n; i++)
    {
        if (s[i].sync_type == SYNC_PHC_SYS ||
            s[i].sync_type == SYNC_PHC_PHC ||
            s[i].sync_type == SYNC_EXANIC_PPS)
        {
            enum phc_source src = get_phc_source(s[i].clkfd, s[i].exanic);

            if (src != PHC_SOURCE_NONE)
            {
                /* Target has another sync source already */
                if (src == PHC_SOURCE_EXANIC_GPS)
                    fprintf(stderr, "%s: clock is already GPS synced\n",
                            s[i].name);
                else
                    fprintf(stderr, "%s: clock has multiple sync sources\n",
                            s[i].name);
                ret = 1;
                goto cleanup;
            }

            set_phc_synced(s[i].clkfd);
        }
        else if (s[i].sync_type == SYNC_SYS_PHC)
        {
            if (sys_synced)
            {
                fprintf(stderr, "%s: system clock has multiple sync sources\n",
                        prog);
                ret = 1;
                goto cleanup;
            }

            sys_synced = 1;
        }
    }

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
                    tai_offset, auto_tai_offset, s[i].offset, s[i].interval);
        else if (s[i].sync_type == SYNC_PHC_PHC)
            s[i].phc_phc_sync = init_phc_phc_sync(s[i].name, s[i].clkfd,
                    s[i].name_src, s[i].clkfd_src, s[i].exanic_src);
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
}
