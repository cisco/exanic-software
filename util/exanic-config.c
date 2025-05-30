#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <linux/sockios.h>
#if HAVE_PTP_CLOCK_H
#include <linux/ptp_clock.h>
#else
#include "ptp_clock_compat.h"
#endif
#include <linux/ethtool.h>
#include "ethtool_compat.h"

#include <exanic/port.h>
#include <exanic/util.h>
#include <exanic/exanic.h>
#include <exanic/config.h>
#include <exanic/register.h>
#include <exanic/firewall.h>
#include <exanic/hw_info.h>
#include <exanic/transceiver.h>
#include <exanic/eeprom.h>
#include "../include/exanic_version.h"

/* X2 and X4 legacy external PHY tuning options */
static const struct
{
    const char *name;
    uint8_t mask;
} phy_params[] = {
    { "rx-gain"       , 0x7f },
    { "rx-preemphasis", 0x1f },
    { "rx-offset"     , 0xff },
    { "tx-gain"       , 0x07 },
    { "tx-preemphasis", 0x1f },
    { "tx-slewrate"   , 0x07 }
};

/* map command line argument to sysfs attribute */
static const struct
{
    const char *param;
    const char *attr;
} phy_sysfs_attrs[] = {
    {"rx-gain"       , "rx_gain"},
    {"rx-preemphasis", "rx_preemphasis"},
    {"rx-offset"     , "rx_offset"},
    {"tx-gain"       , "tx_gain"},
    {"tx-preemphasis", "tx_preemphasis"},
    {"tx-slewrate"   , "tx_slewrate"},
    {"loopback"      , "loopback"}
};


enum conf_option_types {
    CONF_TYPE_BOOLEAN,
    CONF_TYPE_INT8,
    CONF_TYPE_UINT8,
    CONF_TYPE_INT16,
    CONF_TYPE_UINT16,
    CONF_TYPE_INT32,
    CONF_TYPE_UINT32
};

#define CLOCKFD 3
#define FD_TO_CLOCKID(fd) ((~(clockid_t)(fd) << 3) | CLOCKFD)

#define EXANIC_DRIVER_SYSFS_ENTRY "/sys/bus/pci/drivers/exanic"

int parse_number(const char *str)
{
    char *p;
    int num = strtol(str, &p, 0);
    if (*p != '\0' && *p != '\n')
        return -1;
    else
        return num;
}

int parse_signed_number(const char *str, int *num)
{
    char *p;
    *num = strtol(str, &p, 0);
    if (*p != '\0')
        return -1;
    else
        return 0;
}

int parse_on_off(const char *str)
{
    if (strcmp(str, "on") == 0)
        return 1;
    else if (strcmp(str, "off") == 0)
        return 0;
    else
        return -1;
}

int parse_rising_falling(const char *str)
{
    if (strcmp(str, "rising") == 0)
        return 1;
    else if (strcmp(str, "falling") == 0)
        return 0;
    else
        return -1;
}

int parse_device_port(const char *str, char *device, int *port_number)
{
    char *p, *q;

    /* Don't match wildcards */
    p = strchr(str, '*');
    if (p != NULL)
        return -1;
    p = strchr(str, '[');
    if (p != NULL)
        return -1;

    /* Ignore "/dev/" prefix on device name */
    if (strncmp(str, "/dev/", 5) == 0)
        str += 5;

    p = strchr(str, ':');
    if (p == NULL)
    {
        /* No port number provided */
        if (strlen(str) >= 16)
            return -1;
        strcpy(device, str);
        *port_number = -1;
        return 0;
    }
    else
    {
        /* Format is "<device>:<port>" */
        if ((p-str) >= 16)
            return -1;
        strncpy(device, str, p - str);
        device[p - str] = '\0';
        *port_number = strtol(p + 1, &q, 10);
        if (*(p + 1) == '\0' || *q != '\0')
            /* strtol failed */
            return -1;
        return 0;
    }
}

exanic_t * acquire_handle(const char *device)
{
    exanic_t *exanic;
    exanic = exanic_acquire_handle(device);
    if (exanic == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        exit(1);
    }
    if (exanic_check_supported(exanic) == -1)
    {
        /* Print a message but don't exit */
        fprintf(stderr, "%s not supported: %s\n", device, exanic_get_last_error());
    }
    return exanic;
}

void release_handle(exanic_t *exanic)
{
    if (exanic != NULL)
        exanic_release_handle(exanic);
}

void get_interface_name(const char *device, int port_number,
                        char *buf, size_t len)
{
    exanic_t *exanic = acquire_handle(device);
    if (exanic_get_interface_name(exanic, port_number, buf, len) != 0)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number,
                exanic_get_last_error());
        release_handle(exanic);
        exit(1);
    }
    release_handle(exanic);
}

int ethtool_ioctl(int fd, char *ifname, void *data)
{
    struct ifreq ifr;
    size_t ifnamelen = strlen(ifname);

    if (ifnamelen >= IFNAMSIZ)
    {
       errno = ENAMETOOLONG;
       return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ifname, ifnamelen);
    ifr.ifr_data = data;

    return ioctl(fd, SIOCETHTOOL, &ifr);
}

int ethtool_get_priv_flags(int fd, char *ifname, uint32_t *flags)
{
    struct ethtool_value val;
    int ret;

    memset(&val, 0, sizeof(val));
    val.cmd = ETHTOOL_GPFLAGS;
    ret = ethtool_ioctl(fd, ifname, &val);
    if (ret == 0)
        *flags = val.data;

    return ret;
}

int ethtool_set_speed(int fd, char *ifname, uint32_t speed)
{
    struct ethtool_cmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd = ETHTOOL_SSET;
    ethtool_cmd_speed_set(&cmd, speed);

    return ethtool_ioctl(fd, ifname, &cmd);
}

static int ethtool_enable_autoneg(int fd, char* ifname, bool enable, uint32_t speed_mbs)
{

    struct ethtool_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd = ETHTOOL_SSET;
    cmd.autoneg = enable;
    cmd.speed = speed_mbs;

    return ethtool_ioctl(fd, ifname, &cmd);
}

static int restart_autoneg(const char* device, int port_number)
{
    int fd;
    struct ethtool_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    char ifname[IFNAMSIZ];
    cmd.cmd = ETHTOOL_NWAY_RST;
    int ret;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }

    get_interface_name(device, port_number, ifname, IFNAMSIZ);
    ret = ethtool_ioctl(fd, ifname, &cmd);

    close(fd);
    return ret;
}

static int set_fec_via_register_access(const char* device, int port_number, uint32_t fec)
{
    exanic_t *exanic = acquire_handle(device);
    uint32_t caps = exanic_get_caps(exanic);
    uint32_t port_flags;

    if (!IS_25G_SUPPORTED(caps))
    {
        /* there is no support for FEC in cards other than 25G */
        errno = EOPNOTSUPP;
        release_handle(exanic);
        return -1;
    }

    port_flags = exanic_register_read(exanic, REG_PORT_INDEX(port_number, REG_PORT_FLAGS));
    if (port_flags & EXANIC_PORT_FLAG_AUTONEG_ENABLE)
    {
        uint32_t autoneg_caps = exanic_register_read(exanic, REG_EXTENDED_PORT_INDEX(port_number, REG_EXTENDED_PORT_AN_ABILITY));
        autoneg_caps &= ~(EXANIC_AUTONEG_FEC_CAPABILITY_MASK);

        if (fec & ETHTOOL_FEC_RS)
            autoneg_caps |= FEC_CAPABILITY_RS_FEC;
        else if (fec & ETHTOOL_FEC_BASER)
            autoneg_caps |= FEC_CAPABILITY_BASER;

        exanic_register_write(exanic, REG_EXTENDED_PORT_INDEX(port_number, REG_EXTENDED_PORT_AN_ABILITY), autoneg_caps);

        /* restart autoneg */
        exanic_register_write(exanic, REG_EXTENDED_PORT_INDEX(port_number, REG_EXTENDED_PORT_AN_CONTROL), EXANIC_PORT_AUTONEG_RESTART);
        exanic_register_write(exanic, REG_EXTENDED_PORT_INDEX(port_number, REG_EXTENDED_PORT_AN_CONTROL), 0);
    }
    else
    {
        port_flags &= ~(EXANIC_PORT_FLAG_FORCE_FEC_MASK);
        if (fec & ETHTOOL_FEC_RS)
            port_flags |= EXANIC_PORT_FLAG_FORCE_RS_FEC;
        else if (fec & ETHTOOL_FEC_BASER)
            port_flags |= EXANIC_PORT_FLAG_FORCE_BASER_FEC;

        exanic_register_write(exanic, REG_PORT_INDEX(port_number, REG_PORT_FLAGS), port_flags);
    }
    release_handle(exanic);
    return 0;
}

static int ethtool_set_fec(int fd, char* ifname, int port_number, uint32_t fec, const char* device)
{
    int result;
    struct ethtool_fecparam cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd = ETHTOOL_SFECPARAM;
    cmd.fec = fec;

    /* if ethtool_ioctl operation fails because ethtool fec command is not supported
     * then we should fall back to direct register access for fec setup */

    if((result = ethtool_ioctl(fd, ifname, &cmd)) == -1 && errno == EOPNOTSUPP)
        result = set_fec_via_register_access(device, port_number, fec);

    return result;
}

int ethtool_set_priv_flags(int fd, char *ifname, uint32_t flags)
{
    struct ethtool_value val;

    memset(&val, 0, sizeof(val));
    val.cmd = ETHTOOL_SPFLAGS;
    val.data = flags;

    return ethtool_ioctl(fd, ifname, &val);
}

int ethtool_get_flag_names(int fd, char *ifname, char flag_names[32][ETH_GSTRING_LEN])
{
    struct ethtool_drvinfo drvinfo;
    struct ethtool_gstrings *strings;
    unsigned len;

    /* Get number of flags from driver info */
    memset(&drvinfo, 0, sizeof(drvinfo));
    drvinfo.cmd = ETHTOOL_GDRVINFO;
    if (ethtool_ioctl(fd, ifname, &drvinfo) == -1)
        return -1;

    len = drvinfo.n_priv_flags;
    if (len > 32)
        len = 32;

    /* Get flag names */
    strings = calloc(1, sizeof(struct ethtool_gstrings) + len * ETH_GSTRING_LEN);
    if (strings == NULL)
        return -1;

    strings->cmd = ETHTOOL_GSTRINGS;
    strings->string_set = ETH_SS_PRIV_FLAGS;
    strings->len = len;
    if (ethtool_ioctl(fd, ifname, strings) == -1)
    {
        free(strings);
        return -1;
    }

    memset(flag_names, 0, 32 * ETH_GSTRING_LEN);
    memcpy(flag_names, strings->data, len * ETH_GSTRING_LEN);
    free(strings);

    return 0;
}

int ethtool_get_phc_index(int fd, char *ifname, int *phc_index)
{
    struct ethtool_ts_info ts_info;

    memset(&ts_info, 0, sizeof(ts_info));
    ts_info.cmd = ETHTOOL_GET_TS_INFO;
    if (ethtool_ioctl(fd, ifname, &ts_info) == -1)
        return -1;

    *phc_index = ts_info.phc_index;
    return 0;
}

/* return file descriptor to sysfs attributes that control
 * external phy chip parameters */
int x2_x4_open_phy_attr(exanic_t *exanic, int port_number,
                        const char *param)
{
    char syspath[PATH_MAX] = {0};
    char tmp[PATH_MAX + 256];
    const char *sysfs_attr = NULL;
    int fd = 0;

    int i = 0;
    while (i < sizeof phy_sysfs_attrs / sizeof phy_sysfs_attrs[0])
    {
        if (!strcmp(param, phy_sysfs_attrs[i].param))
        {
            sysfs_attr = phy_sysfs_attrs[i].attr;
            break;
        }
        i++;
    }

    if (!sysfs_attr)
        return -1;

    if (exanic_get_sysfs_path(exanic, syspath, sizeof syspath) == -1)
    {
        fprintf(stderr, "%s sysfs path: %s\n",
                        exanic->name, exanic_get_last_error());
        return -1;
    }

    snprintf(tmp, sizeof tmp, "%s/port%d_phy/%s",
                              syspath, port_number, sysfs_attr);
    fd = open(tmp, O_RDWR);
    if (fd == -1)
    {
        fprintf(stderr, "Failed to open \"%s\": %s\n",
                        tmp, strerror(errno));
        return -1;
    }

    return fd;
}

int get_local_loopback(exanic_t *exanic, int port_number)
{
    exanic_hardware_id_t hw_type = exanic_get_hw_type(exanic);
    int loopback = 0;

    if ((hw_type == EXANIC_HW_X4) || (hw_type == EXANIC_HW_X2))
    {
        /* expect '0' or '1' */
        char loopback_status[2];
        int fd = x2_x4_open_phy_attr(exanic, port_number, "loopback");
        if (fd == -1)
            return -1;

        if (read(fd, loopback_status, 1) != 1)
        {
            loopback = -1;
            goto fd_close;
        }

        loopback = loopback_status[0] == '1' ? 1 : 0;
fd_close:
        close(fd);
    }
    else
    {
        uint32_t flags = exanic_register_read(exanic,
                             REG_PORT_INDEX(port_number,
                               REG_PORT_FLAGS));
        loopback = (flags & EXANIC_PORT_FLAG_LOOPBACK) ? 1 : 0;
    }

    return loopback;
}

int get_disable_tx_padding(exanic_t *exanic, int port_number)
{
    int disable_tx_padding = 0;
    uint32_t caps = exanic_get_caps(exanic);

    if (caps & EXANIC_CAP_DISABLE_TX_PADDING)
    {
        uint32_t flags = exanic_register_read(exanic,
                                              REG_PORT_INDEX(port_number,
                                                             REG_PORT_FLAGS));

        disable_tx_padding = (flags & EXANIC_PORT_FLAG_DISABLE_TX_PADDING) ? 1 : 0;
    }
    else
        disable_tx_padding = -1;

    return disable_tx_padding;
}

int get_disable_tx_crc(exanic_t *exanic, int port_number)
{
    int disable_tx_crc = 0;
    uint32_t caps = exanic_get_caps(exanic);

    if (caps & EXANIC_CAP_DISABLE_TX_CRC)
    {
        uint32_t flags = exanic_register_read(exanic,
                                              REG_PORT_INDEX(port_number,
                                                             REG_PORT_FLAGS));

        disable_tx_crc = (flags & EXANIC_PORT_FLAG_DISABLE_TX_CRC) ? 1 : 0;
    }
    else
        disable_tx_crc = -1;

    return disable_tx_crc;
}

void show_serial_number(exanic_t *exanic)
{
    char syspath[PATH_MAX] = {0};
    char tmp[PATH_MAX + 256];
    char serial[64] = {0};
    int fd, ret;

    if (exanic_get_sysfs_path(exanic, syspath, sizeof syspath) == -1)
    {
        fprintf(stderr, "%s sysfs path: %s\n",
                        exanic->name, exanic_get_last_error());
        return;
    }

    snprintf(tmp, sizeof tmp, "%s/serial", syspath);
    fd = open(tmp, O_RDONLY);
    if (fd == -1)
    {
        fprintf(stderr, "Failed to open \"%s\": %s\n",
                        tmp, strerror(errno));
        return;
    }

    /* read serial number from sysfs attribute */
    ret = read(fd, serial, sizeof(serial) - 1);
    if (ret == -1)
    {
        fprintf(stderr, "Failed to read from \"%s\": %s\n",
                        tmp, strerror(errno));
        goto close_file;
    }

    if (ret > 0 && serial[ret - 1] == '\n')
        serial[ret - 1] = '\0';

    printf("  Serial number: %s\n", serial);

close_file:
    close(fd);
}

static void show_port_autoneg_status(const char* device, int port_number, int verbose)
{
    uint32_t autoneg_caps;
    uint32_t autoneg_status, autoneg_lp_ability;
    uint32_t autoneg_lp_tech_ability;

    exanic_t *exanic = acquire_handle(device);

    static const char* tech_ability_bit_to_ethtool_mode [] =
    {
        [AUTONEG_TECH_ABILITY_1000_BASE_KX_BIT_NUM]   = "1000BaseKX",
        [AUTONEG_TECH_ABILITY_10G_BASE_KX4_BIT_NUM]   = "10000BaseKX4",
        [AUTONEG_TECH_ABILITY_10G_BASE_KR_BIT_NUM]    = "10000BaseKR",
        [AUTONEG_TECH_ABILITY_40G_BASE_KR4_BIT_NUM]   = "40000BaseKR4",
        [AUTONEG_TECH_ABILITY_40G_BASE_CR4_BIT_NUM]   = "40000BaseCR4",
        [AUTONEG_TECH_ABILITY_100G_BASE_CR10_BIT_NUM] = "100000BaseCR10",
        [AUTONEG_TECH_ABILITY_100G_BASE_KP4_BIT_NUM]  = "100000BaseKP4",
        [AUTONEG_TECH_ABILITY_100G_BASE_KR4_BIT_NUM]  = "100000BaseKR4",
        [AUTONEG_TECH_ABILITY_100G_BASE_CR4_BIT_NUM]  = "100000BaseCR4",
        [AUTONEG_TECH_ABILITY_25G_BASE_KR_S_BIT_NUM]  = "25000BaseKR_S",
        [AUTONEG_TECH_ABILITY_25G_BASE_KR_BIT_NUM]    = "25000BaseKR",
        [AUTONEG_TECH_ABILITY_END_BIT]                = NULL
    };

    static const char* hcd_string_value [] =
    {
        [UNRESOLVED]   = "unresolved",
        [PMD_10G_KR]   = "10000BaseKR",
        [PMD_40G_CR4]  = "40000BaseCR4",
        [PMD_25G_CR]   = "25000BaseCR",
        [PMD_25G_CR_S] = "25000BaseCR_S",
    };

    static const char* arbiter_state_string[] =
    {
        [EXANIC_PORT_ARBITER_AUTONEG_ENABLE]           = "AUTONEG ENABLE",
        [EXANIC_PORT_ARBITER_TRANSMIT_ENABLE]          = "TRANSMIT DISABLE",
        [EXANIC_PORT_ARBITER_ABILITY_DETECT]           = "ABILITY DETECT",
        [EXANIC_PORT_ARBITER_ACK_DETECT]               = "ACK DETECT",
        [EXANIC_PORT_ARBITER_COMPLETE_ACK]             = "COMPLETE ACK",
        [EXANIC_PORT_ARBITER_NEXT_PAGE_WAIT]           = "NEXT PAGE WAIT",
        [EXANIC_PORT_ARBITER_AN_GOOD_CHECK]            = "AN GOOD CHECK",
        [EXANIC_PORT_ARBITER_AN_GOOD]                  = "AN GOOD",
        [EXANIC_PORT_ARBITER_LINK_STATUS_CHECK]        = "LINK STATUS CHECK",
        [EXANIC_PORT_ARBITER_PARALLEL_DETECTION_FAULT] = "PARALLEL DETECTION FAULT",
        [EXANIC_PORT_ARBITER_END]                      = NULL
    };

    uint32_t caps = exanic_register_read(exanic, REG_EXANIC_INDEX(REG_EXANIC_CAPS));
    uint32_t port_flags = exanic_register_read(exanic, REG_PORT_INDEX(port_number, REG_PORT_FLAGS));
    bool autoneg_enabled = (port_flags & EXANIC_PORT_FLAG_AUTONEG_ENABLE) ? (true) : (false);

    if (!IS_25G_SUPPORTED(caps))
    {
        fprintf(stderr, "This feature is not supported by non-25G compatible ExaNICs\n");
        goto exit;
    }

    printf("Autoneg enable: %s\n", autoneg_enabled ? "on" : "off");
    if (!autoneg_enabled)
        goto exit;

    /* print arbiter state */
    if (verbose)
    {
        uint32_t reg = exanic_register_read(exanic, REG_EXTENDED_PORT_INDEX(port_number, REG_EXTENDED_PORT_AN_ARB_STATE));
        printf("Arbiter state: %s\n" , arbiter_state_string[AUTONEG_ARBITER_STATE(reg)]);
    }

    printf("Advertising modes:\n");
    autoneg_caps = exanic_register_read(exanic, REG_EXTENDED_PORT_INDEX(port_number, REG_EXTENDED_PORT_AN_ABILITY));

    for (int i = 0; i < AUTONEG_TECH_ABILITY_END_BIT; i++)
    {
        const char* s = tech_ability_bit_to_ethtool_mode[i];
        if ((autoneg_caps & (1 << i)) && s != NULL)
            printf("\t%s\n", s);
    }

    printf("Supported FEC:\n");
    if (autoneg_caps & FEC_CAPABILITY_BASER)
        printf("\tBaseR\n");
    if (autoneg_caps & FEC_CAPABILITY_RS_FEC)
        printf("\tRS\n");
    printf("\tOff\n");

    autoneg_status = exanic_register_read(exanic, REG_EXTENDED_PORT_INDEX(port_number, REG_EXTENDED_PORT_AN_STATUS));
    autoneg_lp_ability = exanic_register_read(exanic, REG_EXTENDED_PORT_INDEX(port_number, REG_EXTENDED_PORT_AN_LP_ABILITY));

    if (!(autoneg_status & EXANIC_PORT_AUTONEG_FLAGS_LINK_PARTNER_IS_AUTONEG))
        goto exit;

    printf("Partner advertised modes:\n");
    autoneg_lp_tech_ability = LINK_PARTNER_TECHS(autoneg_lp_ability);
    for (int i = 0; i < AUTONEG_TECH_ABILITY_END_BIT; i++)
    {
        const char* s = tech_ability_bit_to_ethtool_mode[i];
        if ((autoneg_lp_tech_ability & (1 << i)) && s != NULL)
            printf("\t%s\n", s);
    }

    printf("Partner FEC requested: ");
    if (autoneg_lp_ability & FEC_CAPABILITY_BASER)
        printf("BaseR\n");
    else if (autoneg_lp_ability & FEC_CAPABILITY_RS_FEC)
        printf("RS\n");
    else
        printf("Off\n");

    printf("Resolved link mode: %s\n", hcd_string_value[AUTONEG_HCD_VALUE(autoneg_status)]);

    if (autoneg_status & EXANIC_PORT_AUTONEG_FLAGS_RESOLVED_BASER_FEC)
        printf("Resolved FEC: BaseR\n");
    else if (autoneg_status & EXANIC_PORT_AUTONEG_FLAGS_RESOLVED_RS_FEC)
        printf("Resolved FEC: RS\n");
    else
        printf("Resolved FEC: None\n");

exit:
    release_handle(exanic);
}


static void enable_autoneg(const char* device, int port_number, bool enable, uint32_t speed_mbs)
{
    char ifname[IFNAMSIZ];
    int fd;
    get_interface_name(device, port_number, ifname, IFNAMSIZ);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }

    if (ethtool_enable_autoneg(fd, ifname, enable, speed_mbs) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        close(fd);
        exit(1);
    }
    close(fd);
}

static int autoneg_command(const char* progname, const char* device, int port_number, int argc, char* argv[])
{
    exanic_t *exanic = acquire_handle(device);
    uint32_t speed;
    int usage_error = 0;

    if (argc > 0 && strcmp(argv[0], "status") == 0)
    {
        if (argc == 1)
        {
            /* If command is "autoneg status" */
            show_port_autoneg_status(device, port_number, false);
            goto exit;
        }
        else if (argc == 2 && strcmp(argv[1], "-v") == 0)
        {
            /* If command is "autoneg status -v" */
            show_port_autoneg_status(device, port_number, true);
            goto exit;
        }
    }
    else if (argc > 0 && (strcmp(argv[0], "on") == 0))
    {
        /* If command is "autoneg on" */
        /* Do not enable autoneg if it is enabled already */
        if (exanic_port_autoneg_enabled(exanic, port_number))
        {
            printf("%s: autonegotiation already on\n", device);
            goto exit;
        }

        /* Enable autoneg with current speed advertisement only */
        speed = exanic_get_port_speed(exanic, port_number);
        enable_autoneg(device, port_number, true, speed);
        printf("%s: autonegotiation on, advertising %d speed only\n", device, speed);
        goto exit;
    }
    else if (argc > 0 && (strcmp(argv[0], "off") == 0))
    {
        /* If command is "autoneg off" */
        speed = exanic_get_port_speed(exanic, port_number);
        enable_autoneg(device, port_number, false, speed);
        printf("%s: autonegotiation off, speed set to %d\n", device, speed);
        goto exit;
    }
    else if (argc > 0 && (strcmp(argv[0], "restart") == 0))
    {
        /* If command is "autoneg restart" */
        restart_autoneg(device, port_number);
        goto exit;
    }

    usage_error = 1;
exit:
    release_handle(exanic);
    return usage_error;
}

void show_device_info(const char *device, int port_number, int verbose)
{
    int i, first_port, last_port, port_status;
    const char *str;
    exanic_t *exanic;
    exanic_hardware_id_t hw_type;
    exanic_function_id_t function;
    struct exanic_hw_info *hwinfo;
    time_t rev_date;
    uint32_t caps;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        printf("socket creation failed");
        return ;
    }

    exanic = acquire_handle(device);
    hwinfo = &exanic->hw_info;
    hw_type = exanic_get_hw_type(exanic);
    function = exanic_get_function_id(exanic);
    rev_date = exanic_get_hw_rev_date(exanic);
    caps = exanic_get_caps(exanic);

    printf("Device %s:\n", device);

    str = exanic_hardware_id_str(hw_type);
    printf("  Hardware type: %s\n", (str == NULL) ? "unknown" : str);

    if (verbose)
    {
        if (hwinfo->flags & EXANIC_HW_FLAG_DRAM_VARIANT)
        {
            uint32_t ddr_fitted = exanic_register_read(exanic,
                    REG_EXANIC_INDEX(REG_EXANIC_FEATURE_CFG))
                    & EXANIC_STATUS_HW_DRAM_PRES;
            printf("  DDR4 DRAM: %s\n", ddr_fitted ? "present" : "not present");
        }
    }

    show_serial_number(exanic);

    if (hwinfo->hwid != -1)
    {
        uint32_t temp, vccint, vccaux;
        double temp_real=0, vccint_real=0, vccaux_real=0;
        double temp_scal, temp_off, volt_scal;
        unsigned temp_res, volt_res;

        if (hwinfo->dev_family == EXANIC_XILINX_7)
        {
            temp_scal = 503.975;
            temp_off = 273.15;
            temp_res = 1024;
            volt_scal = 3.0;
            volt_res = 1024;
        }
        else if (hwinfo->dev_family == EXANIC_XILINX_US)
        {
            temp_scal = 503.975;
            temp_off = 273.15;
            temp_res = 4096;
            volt_scal = 3.0;
            volt_res = 4096;
        }
        else
        {
            temp_scal = 509.314;
            temp_off = 280.231;
            temp_res = 4096;
            volt_scal = 3.0;
            volt_res = 4096;
        }

        temp = exanic_register_read(exanic, REG_HW_INDEX(REG_HW_TEMPERATURE));
        vccint = exanic_register_read(exanic, REG_HW_INDEX(REG_HW_VCCINT));
        vccaux = exanic_register_read(exanic, REG_HW_INDEX(REG_HW_VCCAUX));

        temp_real = temp * (temp_scal / temp_res) - temp_off;
        vccint_real = vccint * (volt_scal / volt_res);
        vccaux_real = vccaux * (volt_scal / volt_res);

        printf("  Temperature: %.1f C   VCCint: %.2f V   VCCaux: %.2f V\n",
                temp_real, vccint_real, vccaux_real);
    }

    if (hwinfo->flags & EXANIC_HW_FLAG_FAN_RPM_SENSOR)
    {
        uint32_t reg, count, tick_hz;
        double rpm, divisor;

        tick_hz = exanic_register_read(exanic, REG_EXANIC_INDEX(REG_EXANIC_CLK_HZ));
        reg = exanic_register_read(exanic, REG_HW_INDEX(REG_HW_FAN_REV_COUNTER));
        count = reg & 0xFFFFFF;
        divisor = pow(2, (reg >> 24));

        rpm = 60 * 0.5 * count * tick_hz / divisor;

        printf("  Fan speed: %.0f RPM\n", rpm);
    }

    str = exanic_function_id_str(function);
    printf("  Function: %s\n", (str == NULL) ? "unknown" : str);

    {
        char buf[32];
        struct tm *tm;
        char *p;

        tm = gmtime(&rev_date);
        if (tm != NULL)
        {
            asctime_r(tm, buf);
            if ((p = strchr(buf, '\n')) != NULL)
               *p = '\0';

            printf("  Firmware date: %04d%02d%02d (%s)\n", tm->tm_year + 1900,
                tm->tm_mon + 1, tm->tm_mday, buf);
        }
        else
        {
            printf("  Firmware date: unknown \n");
        }
    }

    if (function == EXANIC_FUNCTION_DEVKIT)
    {
        unsigned user_version;
        unsigned application_id;
        user_version = exanic_register_read(exanic,
                        REG_EXANIC_INDEX(REG_EXANIC_DEVKIT_USER_VERSION));
        application_id = exanic_register_read(exanic,
                        REG_EXANIC_INDEX(REG_EXANIC_DEVKIT_APPLICATION_ID));
        printf("  Customer version: %u (%x)%s\n", user_version, user_version,
                                    exanic_is_devkit_free(exanic) ? " (free)" : "");
        if (application_id != 0)
            printf("  Application ID: %u (%x)\n", application_id, application_id);
    }

    if (hwinfo->flags & EXANIC_HW_FLAG_PWR_SENSE)
    {
        uint32_t ext_pwr = exanic_register_read(exanic,
                    REG_HW_INDEX(REG_HW_MISC_GPIO));
        printf("  External 12V power: %s\n", ext_pwr ? "detected" : "not detected");
    }

    if (function == EXANIC_FUNCTION_NIC || function == EXANIC_FUNCTION_PTP_GM)
    {
        if (hw_type != EXANIC_HW_X4 && hw_type != EXANIC_HW_X2)
        {
            uint32_t flags = exanic_register_read(exanic,
                       REG_HW_INDEX(REG_HW_SERIAL_PPS));
            uint32_t config = exanic_register_read(exanic,
                      REG_HW_INDEX(REG_HW_PER_OUT_CONFIG));
            int pps_out = (flags & EXANIC_HW_SERIAL_PPS_OUT_EN) ? 1 : 0;
            int pps_term_en = (flags & EXANIC_HW_SERIAL_PPS_TERM_EN) ? 1 : 0;
            printf("  PPS port: ");
            if (pps_out)
            {
                if (config & EXANIC_HW_PER_OUT_CONFIG_PPS)
                    printf( "1PPS output, on %s edge\n",
                            (flags & EXANIC_HW_SERIAL_PPS_OUT_VAL) ? "rising" : "falling");
                else if (config & EXANIC_HW_PER_OUT_CONFIG_10M)
                    printf( "10MHz output\n");
                else
                    printf( "disabled\n");
            }
            else
            {
                printf("input, termination %s\n", pps_term_en ? "enabled" : "disabled");
            }
        }
    }

    if (function == EXANIC_FUNCTION_NIC)
    {
        /*
         * Check if firmware has bridging support
         * Always available on older cards regardless of capability bit
         */
        if ((caps & EXANIC_CAP_BRIDGING) ||
            hw_type == EXANIC_HW_X4 || hw_type == EXANIC_HW_X2)
        {
            uint32_t reg = exanic_register_read(exanic,
                    REG_EXANIC_INDEX(REG_EXANIC_FEATURE_CFG));
            printf("  Bridging: %s\n", (reg & EXANIC_FEATURE_BRIDGE) ?
                    "on (ports 0 and 1)" : "off");
        }
    }

    if (function == EXANIC_FUNCTION_FIREWALL)
    {
        int fw_capable;
        fw_capable = exanic_get_firewall_capability(exanic);
        printf("  Firewall capability: %s\n", (fw_capable) ? "supported" :
                                                            "unsupported");
    }

    if (function == EXANIC_FUNCTION_DEVKIT && exanic_is_devkit_demo(exanic))
    {
        printf("  **************************************************\n");
        printf("  *** WARNING: THIS CARD HAS EVALUATION FIRMWARE ***\n");
        printf("  *** WHICH WILL CEASE TO FUNCTION AFTER 2 HOURS ***\n");
        printf("  **************************************************\n");
    }

    if (port_number == -1)
    {
        first_port = 0;
        last_port = exanic_get_num_ports(exanic) - 1;
    }
    else
        first_port = last_port = port_number;

    for (i = first_port; i <= last_port; i++)
    {
        int rx_usable, tx_usable;
        char ifname[64];

        memset(ifname, 0, sizeof(ifname));

        if (!exanic_port_configurable(exanic, i))
            continue;

        printf("  Port %d:\n", i);

        rx_usable = exanic_port_rx_usable(exanic, i);
        tx_usable = exanic_port_tx_usable(exanic, i);

        if ((function == EXANIC_FUNCTION_NIC ||
                function == EXANIC_FUNCTION_PTP_GM ||
                    function == EXANIC_FUNCTION_DEVKIT)
                    && rx_usable)
        {
            exanic_get_interface_name(exanic, i, ifname, sizeof(ifname));
            if (strlen(ifname) > 0)
                printf("    Interface: %s\n", ifname);
        }

        printf("    Port speed: %u Mbps\n", exanic_get_port_speed(exanic, i));

        port_status = exanic_get_port_status(exanic, i);
        if (hwinfo->port_ff == EXANIC_PORT_QSFP || hwinfo->port_ff == EXANIC_PORT_QSFPDD)
        {
            /* No signal detected pin on QSFP or QSFPDD. */
            printf("    Port status: %s, %s, %s\n",
                    (port_status & EXANIC_PORT_STATUS_ENABLED) ?
                        "enabled" : "disabled",
                    (port_status & EXANIC_PORT_STATUS_SFP) ?
                        "SFP present" : "no SFP",
                    (port_status & EXANIC_PORT_STATUS_LINK) ?
                        "link active" : "no link");
        }
        else
        {
            printf("    Port status: %s, %s, %s, %s\n",
                    (port_status & EXANIC_PORT_STATUS_ENABLED) ?
                        "enabled" : "disabled",
                    (port_status & EXANIC_PORT_STATUS_SFP) ?
                        "SFP present" : "no SFP",
                    (port_status & EXANIC_PORT_STATUS_SIGNAL) ?
                        "signal detected" : "no signal",
                    (port_status & EXANIC_PORT_STATUS_LINK) ?
                        "link active" : "no link");
        }

        if (function == EXANIC_FUNCTION_NIC &&
            (rx_usable || tx_usable))
        {
            int mirror_supported = 0, rx_mirror = 0, tx_mirror = 0;
            uint32_t reg;

            /* Legacy mirroring configuration bits */
            if (hw_type == EXANIC_HW_X4 || (caps & EXANIC_CAP_MIRRORING))
            {
                reg = exanic_register_read(exanic,
                        REG_EXANIC_INDEX(REG_EXANIC_FEATURE_CFG));
                switch (i)
                {
                    case 0:
                        rx_mirror = (reg & EXANIC_FEATURE_MIRROR_RX_0) != 0;
                        tx_mirror = (reg & EXANIC_FEATURE_MIRROR_TX_0) != 0;
                        break;
                    case 1:
                        rx_mirror = (reg & EXANIC_FEATURE_MIRROR_RX_1) != 0;
                        tx_mirror = (reg & EXANIC_FEATURE_MIRROR_TX_1) != 0;
                        break;
                    case 2:
                        rx_mirror = (reg & EXANIC_FEATURE_MIRROR_RX_2) != 0;
                        tx_mirror = (reg & EXANIC_FEATURE_MIRROR_TX_2) != 0;
                        break;
                }

                if (exanic->num_ports > 0 && i < exanic->num_ports - 1)
                    mirror_supported = 1;
            }

            /* Extended mirroring configuration bits */
            if (caps & EXANIC_CAP_EXT_MIRRORING)
            {
                reg = exanic_register_read(exanic,
                        REG_EXANIC_INDEX(REG_EXANIC_MIRROR_ENABLE_EXT));
                rx_mirror = (reg & (1 << (2 * i))) != 0;
                tx_mirror = (reg & (2 << (2 * i))) != 0;
                mirror_supported = 1;
            }

            if (mirror_supported)
            {
                printf("    Mirroring: %s\n",
                        rx_mirror && tx_mirror ? "RX and TX" :
                        rx_mirror ? "RX only" :
                        tx_mirror ? "TX only" : "off");
            }
        }

        if ((function == EXANIC_FUNCTION_NIC ||
               function == EXANIC_FUNCTION_PTP_GM ||
                 function == EXANIC_FUNCTION_DEVKIT)
                    && rx_usable)
        {
            int loopback, promisc, disable_tx_padding, disable_tx_crc;

            if (verbose)
            {
                int mac_rules = exanic_register_read(exanic,
                                    REG_EXTENDED_PORT_INDEX(i,
                                      REG_EXTENDED_PORT_NUM_MAC_FILTER_RULES));
                int ip_rules = exanic_register_read(exanic,
                                    REG_EXTENDED_PORT_INDEX(i,
                                      REG_EXTENDED_PORT_NUM_IP_FILTER_RULES));
                int tx_size = exanic_register_read(exanic,
                                    REG_PORT_INDEX(i,
                                      REG_PORT_TX_REGION_SIZE)) / 1024;
                printf("    MAC filters: %d", mac_rules);
                printf("  IP filters: %d\n", ip_rules);
                printf("    TX buffer size: %dkB\n", tx_size);
            }

            loopback = get_local_loopback(exanic, i);
            if ((loopback != -1) && (loopback || verbose))
                printf("    Loopback mode: %s\n", loopback ? "on" : "off");

            promisc = exanic_get_promiscuous_mode(exanic, i);
            if ((promisc != -1) && (promisc || verbose))
                printf("    Promiscuous mode: %s\n", promisc ? "on" : "off");

            disable_tx_padding = get_disable_tx_padding(exanic, i);
            if ((disable_tx_padding != -1) && (disable_tx_padding || verbose))
                printf("    TX frame padding: %s\n", disable_tx_padding ? "off" : "on");

            disable_tx_crc = get_disable_tx_crc(exanic, i);
            if ((disable_tx_crc != -1) && (disable_tx_crc || verbose))
                printf("    TX CRCs: %s\n", disable_tx_crc ? "off" : "on");
        }

        if ((function == EXANIC_FUNCTION_NIC ||
                function == EXANIC_FUNCTION_PTP_GM ||
                    function == EXANIC_FUNCTION_DEVKIT)
                && strlen(ifname) > 0)
        {
            char flag_names[32][ETH_GSTRING_LEN];
            uint32_t flags;
            int b, bypass = -1;

            if (ethtool_get_flag_names(fd, ifname, flag_names) == 0 &&
                ethtool_get_priv_flags(fd, ifname, &flags) == 0)
            {
                for (b = 0; b < 32; b++)
                {
                    if (strcmp("bypass_only", flag_names[b]) == 0)
                        bypass = (flags & (1 << b)) ? 1 : 0;
                }
            }

            if ((bypass != -1) && (bypass || verbose))
                printf("    Bypass-only mode: %s\n", bypass ? "on" : "off");
        }

        if ((function == EXANIC_FUNCTION_NIC ||
                function == EXANIC_FUNCTION_PTP_GM ||
                    function == EXANIC_FUNCTION_DEVKIT)
                    && (rx_usable || tx_usable))
        {
            uint8_t mac_addr[6];
            exanic_if_addr_t ifaddr;
            struct in_addr address, netmask;

            memset(mac_addr, 0, sizeof(mac_addr));
            if (exanic_get_mac_addr(exanic, i, mac_addr) == 0)
            {
                printf("    MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        mac_addr[0], mac_addr[1], mac_addr[2],
                        mac_addr[3], mac_addr[4], mac_addr[5]);
            }
            else
            {
                fprintf(stderr, "%s:%d: error reading MAC address: %s\n",
                        device, i, exanic_get_last_error());
            }

            if (exanic_get_interface_addr(exanic, i, &ifaddr) == 0)
            {
                address.s_addr = ifaddr.address;
                netmask.s_addr = ifaddr.netmask;
                if (address.s_addr != INADDR_ANY)
                {
                    printf("    IP address: %s", inet_ntoa(address));
                    printf("  Mask: %s\n", inet_ntoa(netmask));
                }
            }
        }

        if ((function == EXANIC_FUNCTION_NIC ||
                function == EXANIC_FUNCTION_PTP_GM ||
                    function == EXANIC_FUNCTION_DEVKIT)
                    && (rx_usable || tx_usable))
        {
            exanic_port_stats_t port_stats;

            memset(&port_stats, 0, sizeof(port_stats));
            exanic_get_port_stats(exanic, i, &port_stats);
            printf("    RX packets: %u  ignored: %u  error: %u  dropped: %u\n",
                    port_stats.rx_count, port_stats.rx_ignored_count,
                    port_stats.rx_error_count, port_stats.rx_dropped_count);
            printf("    TX packets: %u\n", port_stats.tx_count);
        }
    }

    release_handle(exanic);
    close(fd);
}

void show_all_devices(int verbose, int* ndevices)
{
    DIR *d;
    struct dirent *dir;
    char exanic_file[32];
    int exanic_num;
    int prev_num = -1;
    int num;
    int nnics = 0;

    do
    {
        exanic_num = INT_MAX;
        d = opendir("/dev");
        if (d)
        {
            while ((dir = readdir(d)) != NULL)
            {
                if ((strncmp(dir->d_name, "exanic", 6) == 0) &&
                    ((num = parse_number(dir->d_name + 6)) != -1) &&
                    (num > prev_num) && (num < exanic_num))
                {
                    exanic_num = num;
                    strncpy(exanic_file, dir->d_name, sizeof(exanic_file)-1);
                    exanic_file[sizeof(exanic_file)-1] = 0;
                }
            }
            closedir(d);
        }
        if (exanic_num < INT_MAX)
        {
            show_device_info(exanic_file, -1, verbose);
            prev_num = exanic_num;
            ++nnics;
        }
    }
    while (exanic_num < INT_MAX);
    if (ndevices)
        *ndevices = nnics;
}

void reset_port_counters(const char *device, int port_number)
{
    exanic_t *exanic;
    exanic = acquire_handle(device);
    exanic_register_write(exanic,
                          REG_PORT_STAT_INDEX(port_number, REG_PORT_STAT_RESET),
                          1);
    printf("%s:%d: port counters reset\n", device, port_number);
    release_handle(exanic);
}

int show_sfp_status(const char *device, int port_number)
{
    int port_status;
    exanic_t *exanic;
    struct exanic_hw_info *hwinfo;
    exanic_xcvr_info_t xcvr_info;
    exanic_xcvr_diag_info_t *xcvr_diag_info = NULL;
    const char *xcvr_type_text;

    exanic = acquire_handle(device);
    hwinfo = &exanic->hw_info;
    port_status = exanic_get_port_status(exanic, port_number);

    if ((port_status & EXANIC_PORT_STATUS_SFP) == 0)
    {
        fprintf(stderr, "%s:%d: SFP not present\n", device, port_number);
        release_handle(exanic);
        return 1;
    }

    xcvr_type_text = hwinfo->port_ff == EXANIC_PORT_SFP ? "SFP" :
                     hwinfo->port_ff == EXANIC_PORT_QSFP ? "QSFP" : "QSFPDD";

    if (exanic_get_xcvr_info(exanic, port_number, &xcvr_info) == 0)
    {
        printf("  Vendor: %16.16s PN: %16.16s  rev: %4.4s\n",
               xcvr_info.vendor_name, xcvr_info.vendor_pn,
               xcvr_info.vendor_rev);
        printf("                           SN: %16.16s date: %8.8s\n",
               xcvr_info.vendor_sn, xcvr_info.date_code);

        if (xcvr_info.wavelength)
            printf("  Wavelength: %d nm\n", xcvr_info.wavelength);

        if (xcvr_info.bit_rate)
            printf("  Nominal bit rate: %d Mbps\n", xcvr_info.bit_rate);
    }
    else
        printf("  %s EEPROM not available\n", xcvr_type_text);

    if (exanic_get_xcvr_diag_info(exanic, port_number, &xcvr_diag_info) == 0)
    {
        int i;
        for (i = 0; i < xcvr_diag_info->num_lanes; i++)
        {
            int prefix_len;
            if (xcvr_diag_info->num_lanes > 1)
                prefix_len = printf("  Channel %d ", i);
            else
                prefix_len = printf("  ");

            double rx_pwr = xcvr_diag_info->lanes[i].rx_power * 0.001,
                   tx_pwr = xcvr_diag_info->lanes[i].tx_power * 0.001;

            printf("Rx power: %.1f dBm (%.2f mW)\n",
                   log10(rx_pwr) * 10, rx_pwr);

            printf("%*sTx bias: %.2f mA\n",
                   prefix_len, "",
                   xcvr_diag_info->lanes[i].tx_bias * 0.001);

            printf("%*sTx power: %.1f dBm (%.2f mW)\n",
                   prefix_len, "",
                   log10(tx_pwr) * 10, tx_pwr);
        }

        printf("  Temperature: %.1f C\n", xcvr_diag_info->temp);
        free(xcvr_diag_info);
    }
    else
        printf("  %s diagnostics not available\n", xcvr_type_text);

    release_handle(exanic);
    return 0;
}

void set_port_enable_state(const char *device, int port_number, int mode)
{
    struct ifreq ifr;
    int fd;

    get_interface_name(device, port_number, ifr.ifr_name, IFNAMSIZ);

    /* Enable port via socket ioctls */
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ||
        ioctl(fd, SIOCGIFFLAGS, &ifr) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        close(fd);
        exit(1);
    }

    if (mode)
        ifr.ifr_flags |= IFF_UP;
    else
        ifr.ifr_flags &= ~IFF_UP;

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        close(fd);
        exit(1);
    }

    printf("%s:%d: port %s\n", device, port_number,
            mode ? "enabled" : "disabled");
    close(fd);
}

void set_promiscuous_mode(const char *device, int port_number, int mode)
{
    struct ifreq ifr;
    int fd;

    get_interface_name(device, port_number, ifr.ifr_name, IFNAMSIZ);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }

    /* Enable promisc mode via socket ioctls */
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        close(fd);
        exit(1);
    }

    if (mode)
        ifr.ifr_flags |= IFF_PROMISC;
    else
        ifr.ifr_flags &= ~IFF_PROMISC;

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        close(fd);
        exit(1);
    }

    printf("%s:%d: promiscuous mode %s\n", device, port_number,
            mode ? "enabled" : "disabled");
    close(fd);
}

void set_ethtool_priv_flags(const char *device, int port_number,
                            const char *flag_name, int mode)
{
    char ifname[IFNAMSIZ];
    char flag_names[32][ETH_GSTRING_LEN];
    uint32_t flags = 0;
    unsigned i;
    int fd;

    get_interface_name(device, port_number, ifname, IFNAMSIZ);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }

    /* Get flag names and current setting */
    if (ethtool_get_flag_names(fd, ifname, flag_names) == -1 ||
        ethtool_get_priv_flags(fd, ifname, &flags) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }

    /* Look for flag name */
    for (i = 0; i < 32; i++)
        if (strcmp(flag_name, flag_names[i]) == 0)
            break;
    if (i == 32)
    {
        fprintf(stderr, "%s:%d: could not find flag %s\n", device, port_number,
                flag_name);
        exit(1);
    }

    if (mode)
        flags |= (1 << i);
    else
        flags &= ~(1 << i);

    /* Set flags */
    if (ethtool_set_priv_flags(fd, ifname, flags) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number,
                (errno == EINVAL) ? "Feature not supported on this port"
                                  : strerror(errno));
        exit(1);
    }

    close(fd);
}

void set_speed(const char *device, int port_number, uint32_t speed)
{
    char ifname[IFNAMSIZ];
    int fd;

    get_interface_name(device, port_number, ifname, IFNAMSIZ);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }

    /* Set speed */
    if (ethtool_set_speed(fd, ifname, speed) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number,
                (errno == EINVAL) ? "Requested speed not supported on this port"
                                  : strerror(errno));
        exit(1);
    }

    close(fd);
}

static void set_fec(const char* device, int port_number, const char* fec)
{
    int fd;
    uint32_t ethtool_fec = 0;
    char ifname[IFNAMSIZ];
    static const char* fec_modes_to_ethtool_config_bit[] =
    {
        [ETHTOOL_FEC_NONE_BIT]  = "",
        [ETHTOOL_FEC_AUTO_BIT]  = "auto",
        [ETHTOOL_FEC_OFF_BIT]   = "off",
        [ETHTOOL_FEC_RS_BIT]    = "rs",
        [ETHTOOL_FEC_BASER_BIT] = "baser",
        NULL
    };

    const char** ptr = fec_modes_to_ethtool_config_bit;

    get_interface_name(device, port_number, ifname, IFNAMSIZ);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }

    while(*ptr != NULL)
    {
        if(!strcasecmp(*ptr, fec))
            break;
        ptr++;
    }

    if (*ptr == NULL)
    {
        fprintf(stderr, "%s:%d: Requested fec %s is not found\n", device, port_number, fec);
        close(fd);
        exit(1);
    }

    ethtool_fec = 1 << (ptr - fec_modes_to_ethtool_config_bit);

    if (ethtool_set_fec(fd, ifname, port_number, ethtool_fec, device) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number,
                (errno == EINVAL) ? "Requested fec type not supported on this port"
                                  : strerror(errno));
        close(fd);
        exit(1);
    }

    close(fd);
}

void set_per_out(const char *device, int pps_10m, int enable)
{
    char ifname[IFNAMSIZ];
    char phc_device[32];
    int phc_index;
    int fd, clkfd;
    struct timespec ts;
    struct ptp_perout_request req;

    get_interface_name(device, 0, ifname, IFNAMSIZ);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        fprintf(stderr, "%s: %s\n", device, strerror(errno));
        exit(1);
    }

    phc_index = 0;
    if (ethtool_get_phc_index(fd, ifname, &phc_index) == -1)
    {
        fprintf(stderr, "%s: %s\n", device, strerror(errno));
        close(fd);
        exit(1);
    }

    sprintf(phc_device, "/dev/ptp%d", phc_index);
    if ((clkfd = open(phc_device, O_RDWR)) == -1)
    {
        fprintf(stderr, "%s: %s\n", device, strerror(errno));
        close(fd);
        exit(1);
    }
    if (clock_gettime(FD_TO_CLOCKID(clkfd), &ts) == -1)
    {
        fprintf(stderr, "%s: %s\n", device, strerror(errno));
        close(fd);
        close(clkfd);
        exit(1);
    }

    memset(&req, 0, sizeof(req));
    if (enable)
    {
        req.index = 0;
        if (pps_10m)
        {
            /* PPS */
            req.start.sec = ts.tv_sec + 1;
            req.start.nsec = 0;
            req.period.sec = 1;
            req.period.nsec = 0;
        }
        else
        {
            /* 10M */
            req.start.sec = 0;
            req.start.nsec = 0;
            req.period.sec = 0;
            req.period.nsec = 100;
        }
    }
    if (ioctl(clkfd, PTP_PEROUT_REQUEST, &req) == -1)
    {
        if (errno == EINVAL)
            fprintf(stderr, "%s: %s output not supported on this device\n",
                    device, pps_10m ? "PPS" : "10M");
        else
            fprintf(stderr, "%s: %s\n", device, strerror(errno));
        close(fd);
        close(clkfd);
        exit(1);
    }

    printf("%s: %s output %s\n", device, pps_10m ? "PPS" : "10M",
            enable ? "enabled" : "disabled");
    close(fd);
    close(clkfd);
}

void set_per_out_edge_sel(const char *device, int rising)
{
    exanic_t *exanic;
    exanic = acquire_handle(device);

    uint32_t flags;
    flags = exanic_register_read(exanic, REG_HW_INDEX(REG_HW_SERIAL_PPS));
    if (rising)
        flags = flags | EXANIC_HW_SERIAL_PPS_OUT_VAL;
    else
        flags = flags & (~EXANIC_HW_SERIAL_PPS_OUT_VAL);
    exanic_register_write(exanic, REG_HW_INDEX(REG_HW_SERIAL_PPS), flags);
    printf("%s: Periodic output configured to generate %s edge\n", device, rising ? "rising" : "falling");
    release_handle(exanic);
}

void set_firewall_state(const char *device, exanic_firewall_state_t state)
{
    exanic_t *exanic = acquire_handle(device);
    if (exanic_set_firewall_state(exanic, state) != 0)
    {
        fprintf(stderr, "%s: error changing firewall state: %s\n",
                device, exanic_get_last_error());
        release_handle(exanic);
        exit(1);
    }
    if (state == EXANIC_FIREWALL_ENABLE)
        printf("%s: firewall enabled\n", device);
    else if (state == EXANIC_FIREWALL_DISABLE)
        printf("%s: firewall disabled\n", device);
    else if (state == EXANIC_FIREWALL_TRANSPARENT)
        printf("%s: firewall in transparent mode\n", device);
    release_handle(exanic);
}

int set_local_loopback(const char * device, int port_number, int enable)
{
    exanic_t *exanic = acquire_handle(device);
    exanic_hardware_id_t hw_type = exanic_get_hw_type(exanic);
    int loopback;

    if ((hw_type == EXANIC_HW_X4) || (hw_type == EXANIC_HW_X2))
    {
        char loopback_command[2] = {0};
        int fd;

        int port_status = exanic_get_port_status(exanic, port_number);
        if (!(port_status & EXANIC_PORT_STATUS_ENABLED))
        {
            fprintf(stderr, "%s:%d: cannot enable loopback on disabled port\n", device, port_number);
            goto err_release_handle;
        }

        fd = x2_x4_open_phy_attr(exanic, port_number, "loopback");
        if (fd == -1)
            goto err_release_handle;

        loopback_command[0] = enable ? '1' : '0';
        if (write(fd, loopback_command, sizeof loopback_command) !=
            sizeof loopback_command)
        {
            fprintf(stderr, "%s: error %s loopback: %s\n",
                            device, enable ? "enabling" : "disabling",
                            strerror(errno));
            close(fd);
            goto err_release_handle;
        }

        close(fd);
    }
    else
    {
        uint32_t flags;
        flags = exanic_register_read(exanic, REG_PORT_INDEX(port_number,
                                     REG_PORT_FLAGS));
        if (enable)
            flags |= EXANIC_PORT_FLAG_LOOPBACK;
        else
            flags &= ~EXANIC_PORT_FLAG_LOOPBACK;

        exanic_register_write(exanic, REG_PORT_INDEX(port_number, REG_PORT_FLAGS), flags);
    }

    loopback = get_local_loopback(exanic, port_number);
    if (loopback == -1 || enable != loopback)
    {
        fprintf(stderr, "%s:%d: failed to update loopback mode:"
                        " not supported by firmware?\n", device, port_number);
        goto err_release_handle;
    }

    printf("%s:%d: local-loopback mode %s\n", device, port_number,
            enable ? "enabled" : "disabled");
    release_handle(exanic);
    return 0;

err_release_handle:
    release_handle(exanic);
    return 1;
}


int set_disable_tx_padding(const char *device, int port_number, int enable)
{
    exanic_t *exanic;
    uint32_t caps;
    int disable_tx_padding;
    exanic = acquire_handle(device);
    caps = exanic_get_caps(exanic);

    if (caps & EXANIC_CAP_DISABLE_TX_PADDING)
    {
        uint32_t flags;
        flags = exanic_register_read(exanic, REG_PORT_INDEX(port_number,
                                                            REG_PORT_FLAGS));

        if (enable)
            flags |= EXANIC_PORT_FLAG_DISABLE_TX_PADDING;
        else
            flags &= ~EXANIC_PORT_FLAG_DISABLE_TX_PADDING;

        exanic_register_write(exanic, REG_PORT_INDEX(port_number,
                                                     REG_PORT_FLAGS), flags);
    }

    disable_tx_padding = get_disable_tx_padding(exanic, port_number);

    if (disable_tx_padding == -1 || disable_tx_padding != enable)
    {
        fprintf(stderr, "%s:%d: failed to update TX frame padding:"
                " not supported by firmware\n", device, port_number);

        release_handle(exanic);
        return 1;
    }

    printf("%s:%d: TX frame padding %s\n", device, port_number,
           enable ? "disabled" : "enabled");

    return 0;
}

int set_disable_tx_crc(const char *device, int port_number, int enable)
{
    exanic_t *exanic;
    uint32_t caps;
    int disable_tx_crc;
    exanic = acquire_handle(device);
    caps = exanic_get_caps(exanic);

    if (caps & EXANIC_CAP_DISABLE_TX_CRC)
    {
        uint32_t flags;
        flags = exanic_register_read(exanic, REG_PORT_INDEX(port_number,
                                                            REG_PORT_FLAGS));
        if (enable)
            flags |= EXANIC_PORT_FLAG_DISABLE_TX_CRC;
        else
            flags &= ~EXANIC_PORT_FLAG_DISABLE_TX_CRC;

        exanic_register_write(exanic, REG_PORT_INDEX(port_number,
                                                     REG_PORT_FLAGS), flags);
    }

    disable_tx_crc = get_disable_tx_crc(exanic, port_number);

    if (disable_tx_crc == -1 || disable_tx_crc != enable)
    {
        fprintf(stderr, "%s:%d: failed to update TX CRCs:"
                " not supported by firmware\n", device, port_number);
        goto err_handle_release;
    }

    printf("%s:%d: TX CRCs %s\n", device, port_number,
           enable ? "disabled" : "enabled");
    release_handle(exanic);
    return 0;

err_handle_release:
    release_handle(exanic);
    return 1;
}

int set_phy_parameter(const char *device, int port_number,
                      const char *parameter_name, const char *value_string)
{
    exanic_t *exanic = acquire_handle(device);
    char buf[16] = {0};
    int err = 0;

    int fd = x2_x4_open_phy_attr(exanic, port_number, parameter_name);
    if (fd == -1)
        goto handle_release;

    if (value_string)
    {
        int val = parse_number(value_string);
        size_t len;
        if (val == -1)
        {
            fprintf(stderr, "%s:%d: invalid value specified for %s\n", device,
                    port_number, parameter_name);
            err = 1;
            goto fd_close;
        }

        len = snprintf(buf, sizeof buf, "0x%hhx", (uint8_t)val);
        if (write(fd, buf, len + 1) == -1)
        {
            fprintf(stderr, "%s:%d: failed to write phy parameter: %s\n",
                            device, port_number, strerror(errno));
            err = 1;
            goto fd_close;
        }
    }
    else
    {
        int val;
        if (read(fd, buf, sizeof(buf) - 1) == -1)
        {
            fprintf(stderr, "%s: %d: failed to read phy parameter: %s\n",
                            device, port_number, strerror(errno));
            err = 1;
            goto fd_close;
        }

        val = parse_number(buf);
        if (val == -1)
        {
            fprintf(stderr, "%s: invalid value returned from driver: \"%s\"\n",
                            device, buf);
            err = 1;
            goto fd_close;
        }

        printf("%s:%d: %s = %hhu\n", device, port_number,
                                     parameter_name, (uint8_t)val);
    }

fd_close:
    close(fd);
handle_release:
    release_handle(exanic);
    return err;
}

int show_phy_parameters(const char *device, int port_number)
{
    exanic_t *exanic = acquire_handle(device);
    char buf[16] = {0};
    int err = 0;

    int i;
    for (i = 0; i < sizeof phy_params/sizeof phy_params[0]; i++)
    {
        const char *param = phy_params[i].name;
        uint8_t mask = phy_params[i].mask;
        int val;
        int fd = x2_x4_open_phy_attr(exanic, port_number, param);
        if (fd == -1)
        {
            err = 1;
            goto handle_release;
        }

        if (read(fd, buf, sizeof(buf) - 1) == -1)
        {
            fprintf(stderr, "%s:%d: error reading phy parameter \"%s\": %s\n",
                            device, port_number, param, strerror(errno));
            goto fd_close;
        }

        val = parse_number(buf);
        if (val == -1)
        {
            fprintf(stderr, "%s: invalid value returned from driver: \"%s\"\n",
                            device, buf);
            goto fd_close;
        }

        printf("%s:%d: %s = %hhu (range 0..%u)\n", device, port_number,
                                                   param, (uint8_t)val, mask);

fd_close:
        close(fd);
    }

handle_release:
    release_handle(exanic);
    return err;
}

void show_firewall_filters(const char *device)
{
    int i;
    int num_filters, max_filters;
    exanic_t *exanic;
    char filter[256];

    exanic = acquire_handle(device);
    num_filters = 0;
    max_filters = exanic_get_num_firewall_filters(exanic);
    if (max_filters == -1)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        release_handle(exanic);
        exit(1);
    }

    printf("Firewall filters on %s:\n", device);

    for (i = 0; i < max_filters; i++)
    {
        if (exanic_get_firewall_filter(exanic, i, filter, sizeof(filter)) == -1)
        {
            fprintf(stderr, "%s: error on filter %d: %s\n",
                    device, i, exanic_get_last_error());
            release_handle(exanic);
            exit(1);
        }
        if (strlen(filter) > 0)
        {
            printf("%4u: %s\n", i, filter);
            num_filters++;
        }
    }

    printf("%d used, %d total\n", num_filters, max_filters);

    release_handle(exanic);
}


void show_firewall_dump(const char *device)
{
    int i;
    int max_filters;
    exanic_t *exanic;
    char filter[256];
    exanic_firewall_state_t fw_state;

    exanic = acquire_handle(device);
    fw_state = exanic_get_firewall_state(exanic);
    max_filters = exanic_get_num_firewall_filters(exanic);
    if (max_filters == -1)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        release_handle(exanic);
        exit(1);
    }

    printf("filters:%d\n", max_filters);

    if (fw_state == EXANIC_FIREWALL_DISABLE)
        printf("mode:disabled\n");
    else if (fw_state == EXANIC_FIREWALL_ENABLE)
        printf("mode:enabled\n");
    else if (fw_state == EXANIC_FIREWALL_TRANSPARENT)
        printf("mode:transparent\n");

    for (i = 0; i < max_filters; i++)
    {
        if (exanic_get_firewall_filter(exanic, i, filter, sizeof(filter)) == -1)
        {
            fprintf(stderr, "%s: error on filter %d: %s\n",
                    device, i, exanic_get_last_error());
            release_handle(exanic);
            exit(1);
        }
        if (strlen(filter) > 0)
            printf("%u:%s\n", i, filter);
    }

    release_handle(exanic);
}

void set_firewall_filter(const char *device, int slot, const char *filter)
{
    char buf[256];
    exanic_t *exanic = acquire_handle(device);
    if (exanic_get_firewall_filter(exanic, slot, buf, sizeof(buf)) == 0
            && strlen(buf) > 0)
    {
        fprintf(stderr, "%s: error setting firewall filter: "
                "filter %d is already in use\n",
                device, slot);
        release_handle(exanic);
        exit(1);
    }
    if (exanic_set_firewall_filter(exanic, slot, filter) == -1)
    {
        fprintf(stderr, "%s: error setting firewall filter: %s\n",
                device, exanic_get_last_error());
        release_handle(exanic);
        exit(1);
    }
    printf("%s: added firewall filter %d: %s\n", device, slot, filter);
    release_handle(exanic);
}

void clear_firewall_filter(const char *device, int slot)
{
    exanic_t *exanic = acquire_handle(device);
    if (exanic_clear_firewall_filter(exanic, slot) == -1)
    {
        fprintf(stderr, "%s: error deleting firewall filter: %s\n",
                device, exanic_get_last_error());
        release_handle(exanic);
        exit(1);
    }
    printf("%s: deleted firewall filter %d\n", device, slot);
    release_handle(exanic);
}

void clear_all_firewall_filters(const char *device)
{
    exanic_t *exanic = acquire_handle(device);
    if (exanic_clear_all_firewall_filters(exanic) == -1)
    {
        fprintf(stderr, "%s: error deleting firewall filters: %s\n",
                device, exanic_get_last_error());
        release_handle(exanic);
        exit(1);
    }
    printf("%s: deleted all firewall filters\n", device);
    release_handle(exanic);
}

const char *gps_fix_str(uint32_t id)
{
    switch (id)
    {
        case EXANIC_PTP_GPS_STATUS_FIX_NONE:
            return "no fix";
        case EXANIC_PTP_GPS_STATUS_FIX_2D:
            return "2D fix";
        case EXANIC_PTP_GPS_STATUS_FIX_3D:
            return "3D fix";
        default:
            return "unknown";
    }
}

const char *pow2_str(int8_t l)
{
    static char buf[64];

    if (l < 0)
        sprintf(buf, "1/%llu", 1ULL<<-l);
    else
        sprintf(buf, "%llu", 1ULL<<l);

    return buf;
}

/* Read 64 bit hardware time, correcting for rollover */
void read_hw_time(exanic_t *exanic, struct timespec *hw_time)
{
    uint32_t tick_hz;
    uint64_t time_ticks;
    uint32_t hi1, hi2, lo;

    hi1 = exanic_register_read(exanic, REG_EXANIC_INDEX(REG_EXANIC_HW_TIME_HI));
    lo = exanic_register_read(exanic, REG_EXANIC_INDEX(REG_EXANIC_HW_TIME));
    hi2 = exanic_register_read(exanic, REG_EXANIC_INDEX(REG_EXANIC_HW_TIME_HI));
    tick_hz = exanic->tick_hz;

    if (hi1 == hi2)
        time_ticks = ((uint64_t)hi1) << 32 | lo;
    else if (lo < 0x80000000)
        time_ticks = ((uint64_t)hi2) << 32 | lo;
    else
        time_ticks = ((uint64_t)hi1) << 32 | lo;

    hw_time->tv_sec = time_ticks / tick_hz;
    hw_time->tv_nsec = (time_ticks % tick_hz) * 1000000000 / tick_hz;
}

void show_ptp_status(const char *device)
{
    exanic_t *exanic;
    uint32_t conf0, conf1, conf2, gps_status, num_clients, num_unicast_clients,
             ptp_frames_tx, ptp_frames_rx, tai_offset, holdover;
    uint32_t acc;
    int8_t log_announce_interval, log_sync_interval;
    uint8_t announce_receipt_timeout;
    int16_t antenna_cable_delay;
    uint8_t gps_fix, gps_num_sats, clock_state, port_state;
    struct in_addr ipaddr;
    char buffer[64];
    uint8_t mac_addr[6];
    uint32_t mac_addr_int;
    struct timespec hw_time, utc_time;

    exanic = acquire_handle(device);

    conf0 = exanic_register_read(exanic, REG_PTP_INDEX(REG_PTP_CONF0));
    conf1 = exanic_register_read(exanic, REG_PTP_INDEX(REG_PTP_CONF1));
    conf2 = exanic_register_read(exanic, REG_PTP_INDEX(REG_PTP_CONF2));
    ipaddr.s_addr = exanic_register_read(exanic,
            REG_PTP_INDEX(REG_PTP_IP_ADDR));
    gps_status = exanic_register_read(exanic,
            REG_PTP_INDEX(REG_PTP_GPS_STATUS));
    num_clients = exanic_register_read(exanic,
            REG_PTP_INDEX(REG_PTP_NUM_CLIENTS));
    acc = exanic_register_read(exanic, REG_PTP_INDEX(REG_PTP_CLOCK_ACCURACY));
    ptp_frames_tx = exanic_register_read(exanic,
            REG_PTP_INDEX(REG_PTP_FRAMES_TX));
    ptp_frames_rx = exanic_register_read(exanic,
            REG_PTP_INDEX(REG_PTP_FRAMES_RX));
    tai_offset = exanic_register_read(exanic,
            REG_PTP_INDEX(REG_PTP_TAI_OFFSET));
    holdover = exanic_register_read(exanic,
            REG_PTP_INDEX(REG_PTP_HOLDOVER_DURATION));
    port_state = exanic_register_read(exanic,
            REG_PTP_INDEX(REG_PTP_PORT_STATE));
    read_hw_time(exanic, &hw_time);

    num_unicast_clients = num_clients;
    if ((conf0 & EXANIC_PTP_CONF0_ETH_MULTICAST) && num_unicast_clients > 0)
        num_unicast_clients--;
    if ((conf0 & EXANIC_PTP_CONF0_IP_MULTICAST) && num_unicast_clients > 0)
        num_unicast_clients--;
    gps_fix = (gps_status & EXANIC_PTP_GPS_STATUS_FIX_MASK);
    gps_num_sats = ((gps_status & EXANIC_PTP_GPS_STATUS_NUM_SATS_MASK) >>
            EXANIC_PTP_GPS_STATUS_NUM_SATS_SHIFT);
    clock_state = ((gps_status & EXANIC_PTP_GPS_STATUS_CLOCK_STATE_MASK) >>
            EXANIC_PTP_GPS_STATUS_CLOCK_STATE_SHIFT);

    log_announce_interval = (int8_t)
        ((conf1 & EXANIC_PTP_CONF1_ANNOUNCE_INTERVAL_MASK) >>
            EXANIC_PTP_CONF1_ANNOUNCE_INTERVAL_SHIFT);
    log_sync_interval = (int8_t)
        ((conf1 & EXANIC_PTP_CONF1_SYNC_INTERVAL_MASK) >>
            EXANIC_PTP_CONF1_SYNC_INTERVAL_SHIFT);
    announce_receipt_timeout = (uint8_t)
        ((conf2 & EXANIC_PTP_CONF2_ANNOUNCE_RECEIPT_TIMEOUT_MASK) >>
            EXANIC_PTP_CONF2_ANNOUNCE_RECEIPT_TIMEOUT_SHIFT);

    antenna_cable_delay = (int16_t)
        ((conf2 & EXANIC_PTP_CONF2_ANTENNA_CABLE_DELAY_MASK) >>
            EXANIC_PTP_CONF2_ANTENNA_CABLE_DELAY_SHIFT);

    printf("Device %s:\n", device);
    printf("  PTP grandmaster: %s\n",
            (conf0 & EXANIC_PTP_CONF0_PTP_ENABLE) ? "enabled" : "disabled");

    printf("  Synchronize to GPS time: %s\n",
            (conf0 & EXANIC_PTP_CONF0_GPS_CLOCK_SYNC) ? "enabled" : "disabled");
    if ((conf0 & EXANIC_PTP_CONF0_GPS_CLOCK_SYNC) != 0)
    {
        struct tm *tm;

        utc_time.tv_sec = hw_time.tv_sec - tai_offset;
        utc_time.tv_nsec = hw_time.tv_nsec;
        tm = gmtime(&hw_time.tv_sec);
        if (tm)
            strftime(buffer, sizeof(buffer), "%F %T", tm);
        else
            snprintf(buffer, sizeof(buffer), "Invalid");
        printf("  Hardware time: %s.%09ld TAI\n", buffer, hw_time.tv_nsec);
        tm = gmtime(&utc_time.tv_sec);
        if (tm)
            strftime(buffer, sizeof(buffer), "%F %T", tm);
        else
            snprintf(buffer, sizeof(buffer), "Invalid");
        printf("                 %s.%09ld UTC\n", buffer, utc_time.tv_nsec);
        printf("  TAI-UTC offset: %ds\n", tai_offset);
    }
    memset(mac_addr, 0, sizeof(mac_addr));
    if (exanic_get_mac_addr(exanic, 0, mac_addr) == 0)
    {
        mac_addr_int = (mac_addr[3] << 16) + (mac_addr[4] << 8) + mac_addr[5];
        mac_addr_int += 2;   /* GM MAC is hardcoded to be PORT0+2  */
        printf("  MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                mac_addr[0], mac_addr[1], mac_addr[2],
                (mac_addr_int>>16), (mac_addr_int>>8) & 0xFF,
                mac_addr_int & 0xFF );
    }
    else
    {
        fprintf(stderr, "%s:%d: error reading MAC address: %s\n",
                device, 0, exanic_get_last_error());
    }

    printf("  PTP configuration:\n");
    printf("    Ethernet multicast: %s\n",
            (conf0 & EXANIC_PTP_CONF0_ETH_MULTICAST) ? "on" : "off");
    printf("    IPv4 multicast: %s\n",
            (conf0 & EXANIC_PTP_CONF0_IP_MULTICAST) ? "on" : "off");
    printf("    IPv4 unicast negotiation: %s\n",
            (conf0 & EXANIC_PTP_CONF0_IP_UNICAST) ? "on" : "off");
    printf("    IPv4 address: %s\n", inet_ntoa(ipaddr));
    printf("    PTP domain: %u\n",
            ((conf0 & EXANIC_PTP_CONF0_DOMAIN_MASK) >>
             EXANIC_PTP_CONF0_DOMAIN_SHIFT));
    printf("    PTP priority 1: %u\n",
            ((conf0 & EXANIC_PTP_CONF0_PRIORITY1_MASK) >>
             EXANIC_PTP_CONF0_PRIORITY1_SHIFT));
    printf("    PTP priority 2: %u\n",
            ((conf0 & EXANIC_PTP_CONF0_PRIORITY2_MASK) >>
             EXANIC_PTP_CONF0_PRIORITY2_SHIFT));
    printf("    Multicast announce interval: %d (%ss)\n",
            log_announce_interval, pow2_str(log_announce_interval));
    printf("    Multicast sync interval: %d (%ss)\n",
            log_sync_interval, pow2_str(log_sync_interval));
    printf("    Announce receipt timeout: %d (%gs)\n", announce_receipt_timeout,
            announce_receipt_timeout * pow(2, log_announce_interval));

    printf("    One-step or two-step clock: %s\n",
            (conf1 & EXANIC_PTP_CONF1_PTP_TWO_STEP_EN) ? "two-step" : "one-step");

    printf("  GPS configuration:\n");
    printf("    Antenna cable delay: %dns\n", antenna_cable_delay);

    printf("  GPS receiver status:\n");
    printf("    Fix type: %s\n", gps_fix_str(gps_fix));
    printf("    Number of tracked satellites: %u\n", gps_num_sats);
    if ((conf0 & EXANIC_PTP_CONF0_GPS_CLOCK_SYNC) != 0)
    {
        printf("  Clock status:\n");
        printf("    Sync state: ");
        if (clock_state == EXANIC_PTP_CLOCK_STATE_UNSYNCED)
            printf("not synced\n");
        else if (clock_state == EXANIC_PTP_CLOCK_STATE_SYNCED)
            printf("synced\n");
        else if (clock_state == EXANIC_PTP_CLOCK_STATE_WAITING)
            printf("waiting for sync\n");
        else if (clock_state == EXANIC_PTP_CLOCK_STATE_WARMUP)
            printf("warming up\n");
        else if (clock_state == EXANIC_PTP_CLOCK_STATE_HOLDOVER)
            printf("holdover (%ds)\n", holdover);
        printf("    Estimated clock accuracy: ");
        if (acc == 0xFFFFFFFF)
            printf("unknown\n");
        else
            printf("%dns\n", acc);
    }
    printf("  PTP grandmaster status:\n");

    printf("    PTP port state: ");
    if (port_state == EXANIC_PTP_PORT_STATE_INITIALIZING)
        printf("initializing\n");
    else if (port_state == EXANIC_PTP_PORT_STATE_FAULTY)
        printf("faulty\n");
    else if (port_state == EXANIC_PTP_PORT_STATE_DISABLED)
        printf("disabled\n");
    else if (port_state == EXANIC_PTP_PORT_STATE_LISTENING)
        printf("listening\n");
    else if (port_state == EXANIC_PTP_PORT_STATE_PRE_MASTER)
        printf("pre master\n");
    else if (port_state == EXANIC_PTP_PORT_STATE_MASTER)
        printf("master\n");
    else if (port_state == EXANIC_PTP_PORT_STATE_PASSIVE)
        printf("passive\n");
    else if (port_state == EXANIC_PTP_PORT_STATE_UNCALIBRATED)
        printf("uncalibrated\n");
    else if (port_state == EXANIC_PTP_PORT_STATE_SLAVE)
        printf("slave\n");
    else
        printf("unknown\n");

    printf("    Number of unicast clients: %u\n", num_unicast_clients);
    printf("    PTP packets sent: %u\n", ptp_frames_tx);
    printf("    PTP packets received: %u\n", ptp_frames_rx);

    release_handle(exanic);
}

struct ptp_conf_option {
    const char *name;
    enum conf_option_types type;
    int min;
    int max;
    int reg;
    uint32_t mask;
    unsigned shift;
    int default_value;
};

struct ptp_conf_option ptp_conf_options[] = {
    { "eth-multicast", CONF_TYPE_BOOLEAN, 0, 1,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_ETH_MULTICAST, 0, 0 },
    { "ip-multicast", CONF_TYPE_BOOLEAN, 0, 1,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_IP_MULTICAST, 0, 0 },
    { "ip-unicast", CONF_TYPE_BOOLEAN, 0, 1,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_IP_UNICAST, 0, 0 },
    { "gps-sync", CONF_TYPE_BOOLEAN, 0, 1,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_GPS_CLOCK_SYNC, 0, 1 },
    { "domain", CONF_TYPE_UINT8, 0, 127,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_DOMAIN_MASK,
                       EXANIC_PTP_CONF0_DOMAIN_SHIFT, 0 },
    { "priority1", CONF_TYPE_UINT8, 0, 255,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_PRIORITY1_MASK,
                       EXANIC_PTP_CONF0_PRIORITY1_SHIFT, 128 },
    { "priority2", CONF_TYPE_UINT8, 0, 255,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_PRIORITY2_MASK,
                       EXANIC_PTP_CONF0_PRIORITY2_SHIFT, 128 },
    { "announce-interval", CONF_TYPE_INT8, -5, 5,
        REG_PTP_CONF1, EXANIC_PTP_CONF1_ANNOUNCE_INTERVAL_MASK,
                       EXANIC_PTP_CONF1_ANNOUNCE_INTERVAL_SHIFT, 1 },
    { "sync-interval", CONF_TYPE_INT8, -5, 5,
        REG_PTP_CONF1, EXANIC_PTP_CONF1_SYNC_INTERVAL_MASK,
                       EXANIC_PTP_CONF1_SYNC_INTERVAL_SHIFT, 0 },
    { "announce-receipt-timeout", CONF_TYPE_UINT8, 2, 10,
        REG_PTP_CONF2, EXANIC_PTP_CONF2_ANNOUNCE_RECEIPT_TIMEOUT_MASK,
                       EXANIC_PTP_CONF2_ANNOUNCE_RECEIPT_TIMEOUT_SHIFT, 3 },
    { "antenna-cable-delay", CONF_TYPE_INT16, -32768, 32767,
        REG_PTP_CONF2, EXANIC_PTP_CONF2_ANTENNA_CABLE_DELAY_MASK,
                       EXANIC_PTP_CONF2_ANTENNA_CABLE_DELAY_SHIFT, 0 },
};

struct ptp_conf_option ptp_default_profile_options[] = {
    { "eth-multicast", CONF_TYPE_BOOLEAN, 0, 1,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_ETH_MULTICAST, 0, 0 },
    { "ip-multicast", CONF_TYPE_BOOLEAN, 0, 1,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_IP_MULTICAST, 0, 1 },
    { "ip-unicast", CONF_TYPE_BOOLEAN, 0, 1,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_IP_UNICAST, 0, 0 },
    { "gps-sync", CONF_TYPE_BOOLEAN, 0, 1,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_GPS_CLOCK_SYNC, 0, 1 },
    { "domain", CONF_TYPE_UINT8, 0, 127,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_DOMAIN_MASK,
                       EXANIC_PTP_CONF0_DOMAIN_SHIFT, 0 },
    { "priority1", CONF_TYPE_UINT8, 0, 255,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_PRIORITY1_MASK,
                       EXANIC_PTP_CONF0_PRIORITY1_SHIFT, 128 },
    { "priority2", CONF_TYPE_UINT8, 0, 255,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_PRIORITY2_MASK,
                       EXANIC_PTP_CONF0_PRIORITY2_SHIFT, 128 },
    { "announce-interval", CONF_TYPE_INT8, 0, 4,
        REG_PTP_CONF1, EXANIC_PTP_CONF1_ANNOUNCE_INTERVAL_MASK,
                       EXANIC_PTP_CONF1_ANNOUNCE_INTERVAL_SHIFT, 1 },
    { "sync-interval", CONF_TYPE_INT8, -1, 1,
        REG_PTP_CONF1, EXANIC_PTP_CONF1_SYNC_INTERVAL_MASK,
                       EXANIC_PTP_CONF1_SYNC_INTERVAL_SHIFT, 0 },
    { "announce-receipt-timeout", CONF_TYPE_UINT8, 2, 10,
        REG_PTP_CONF2, EXANIC_PTP_CONF2_ANNOUNCE_RECEIPT_TIMEOUT_MASK,
                       EXANIC_PTP_CONF2_ANNOUNCE_RECEIPT_TIMEOUT_SHIFT, 3 },
    { "antenna-cable-delay", CONF_TYPE_INT16, -32768, 32767,
        REG_PTP_CONF2, EXANIC_PTP_CONF2_ANTENNA_CABLE_DELAY_MASK,
                       EXANIC_PTP_CONF2_ANTENNA_CABLE_DELAY_SHIFT, 0 },
};


struct ptp_conf_option ptp_telecom_profile_options[] = {
    { "eth-multicast", CONF_TYPE_BOOLEAN, 0, 1,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_ETH_MULTICAST, 0, 0 },
    { "ip-multicast", CONF_TYPE_BOOLEAN, 0, 1,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_IP_MULTICAST, 0, 0 },
    { "ip-unicast", CONF_TYPE_BOOLEAN, 0, 1,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_IP_UNICAST, 0, 1 },
    { "gps-sync", CONF_TYPE_BOOLEAN, 0, 1,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_GPS_CLOCK_SYNC, 0, 1 },
    { "domain", CONF_TYPE_UINT8, 4, 23,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_DOMAIN_MASK,
                       EXANIC_PTP_CONF0_DOMAIN_SHIFT, 4 },
    { "priority1", CONF_TYPE_UINT8, 0, 255,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_PRIORITY1_MASK,
                       EXANIC_PTP_CONF0_PRIORITY1_SHIFT, 128 },
    { "priority2", CONF_TYPE_UINT8, 0, 255,
        REG_PTP_CONF0, EXANIC_PTP_CONF0_PRIORITY2_MASK,
                       EXANIC_PTP_CONF0_PRIORITY2_SHIFT, 128 },
    { "announce-interval", CONF_TYPE_INT8, -3, 4,
        REG_PTP_CONF1, EXANIC_PTP_CONF1_ANNOUNCE_INTERVAL_MASK,
                       EXANIC_PTP_CONF1_ANNOUNCE_INTERVAL_SHIFT, 1 },
    { "sync-interval", CONF_TYPE_INT8, -7, 4,
        REG_PTP_CONF1, EXANIC_PTP_CONF1_SYNC_INTERVAL_MASK,
                       EXANIC_PTP_CONF1_SYNC_INTERVAL_SHIFT, 0 },
    { "announce-receipt-timeout", CONF_TYPE_UINT8, 2, 2,
        REG_PTP_CONF2, EXANIC_PTP_CONF2_ANNOUNCE_RECEIPT_TIMEOUT_MASK,
                       EXANIC_PTP_CONF2_ANNOUNCE_RECEIPT_TIMEOUT_SHIFT, 2 },
    { "antenna-cable-delay", CONF_TYPE_INT16, -32768, 32767,
        REG_PTP_CONF2, EXANIC_PTP_CONF2_ANTENNA_CABLE_DELAY_MASK,
                       EXANIC_PTP_CONF2_ANTENNA_CABLE_DELAY_SHIFT, 0 },
};

struct ptp_conf_option *ptp_options = NULL;
int ptp_num_options = 0;
int ptp_profile;

void ptp_write_conf(const char *device,
        const struct ptp_conf_option *opt, uint32_t val)
{
    exanic_t *exanic;
    uint32_t conf;

    exanic = acquire_handle(device);

    conf = exanic_register_read(exanic, REG_PTP_INDEX(opt->reg));
    conf &= ~opt->mask;
    if (opt->type == CONF_TYPE_BOOLEAN)
        conf |= (val ? opt->mask : 0);
    else
        conf |= ((val << opt->shift) & opt->mask);
    exanic_register_write(exanic, REG_PTP_INDEX(opt->reg), conf);

    release_handle(exanic);
}

uint32_t ptp_read_conf(const char *device, const struct ptp_conf_option *opt)
{
    exanic_t *exanic;
    uint32_t conf, val;

    exanic = acquire_handle(device);

    conf = exanic_register_read(exanic, REG_PTP_INDEX(opt->reg));

    if (opt->type == CONF_TYPE_BOOLEAN)
        val = (conf & opt->mask) ? 1 : 0;
    else
        val = ((conf & opt->mask) >> opt->shift);

    release_handle(exanic);

    return val;
}

int ptp_save_conf(const char *device)
{
    exanic_t *exanic;
    exanic_eeprom_t *eeprom;
    int addresses[] = { 0x20, 0x24, 0x28, 0x2C };
    int registers[] = { REG_PTP_IP_ADDR, REG_PTP_CONF0,
                        REG_PTP_CONF1, REG_PTP_CONF2 };
    int i;
    int err = 0;

    exanic = acquire_handle(device);
    eeprom = exanic_eeprom_acquire(exanic);
    if (eeprom == NULL)
    {
        fprintf(stderr, "%s: error acquiring eeprom: %s\n",
                        device, exanic_get_last_error());
        return -1;
    }

    for (i = 0; i < sizeof(addresses)/sizeof(int); i++)
    {
        uint32_t reg = exanic_register_read(exanic, REG_PTP_INDEX(registers[i]));
        err = exanic_eeprom_write(eeprom, addresses[i], sizeof reg,
                                  (const uint8_t *)&reg);
        if (err)
        {
            fprintf(stderr, "%s: error saving PTP configuration: %s\n",
                    device, exanic_get_last_error());
            goto handle_release;
        }
    }

    printf("%s: PTP configuration saved to EEPROM\n", device);

handle_release:
    exanic_eeprom_free(eeprom);
    release_handle(exanic);
    return err;
}

int ptp_read_profile(const char *device)
{
    int profile;
    uint32_t conf;
    exanic_t *exanic;

    exanic = acquire_handle(device);
    conf = exanic_register_read(exanic, REG_PTP_INDEX(REG_PTP_CONF1));
    release_handle(exanic);

    profile = ((conf & EXANIC_PTP_CONF1_PTP_PROFILE_MASK) >>
            EXANIC_PTP_CONF1_PTP_PROFILE_SHIFT);

    return profile;
}

void ptp_set_ip_address(const char *device, struct in_addr *ipaddr)
{
    exanic_t *exanic;

    exanic = acquire_handle(device);
    exanic_register_write(exanic, REG_PTP_INDEX(REG_PTP_IP_ADDR),
            ipaddr->s_addr);
    printf("%s: IP address set to %s\n", device, inet_ntoa(*ipaddr));
    release_handle(exanic);
}

void ptp_load_profile_defaults(const char *device)
{
    uint32_t conf;
    int profile;
    exanic_t *exanic;

    exanic = acquire_handle(device);
    conf = exanic_register_read(exanic, REG_PTP_INDEX(REG_PTP_CONF1));
    release_handle(exanic);

    profile = ((conf & EXANIC_PTP_CONF1_PTP_PROFILE_MASK) >>
            EXANIC_PTP_CONF1_PTP_PROFILE_SHIFT);

    /*
     * set the global options struct which will manage min, max and
     * default value
     */
    if (profile == DEFAULT_PROFILE)
    {
        ptp_profile = profile;
        ptp_options = ptp_default_profile_options;
        ptp_num_options = sizeof(ptp_default_profile_options) /
                sizeof(struct ptp_conf_option);
    }
    else if (profile == TELECOM_PROFILE)
    {
        ptp_profile = profile;
        ptp_options = ptp_telecom_profile_options;
        ptp_num_options = sizeof(ptp_telecom_profile_options) /
                sizeof(struct ptp_conf_option);
    }
    else
    {
        /* default to no profile settings */
        ptp_profile = NO_PROFILE;
        ptp_options = ptp_conf_options;
        ptp_num_options = sizeof(ptp_conf_options) /
                sizeof(struct ptp_conf_option);
    }
}

void ptp_apply_profile_defaults(const char *device)
{
    int i;

    printf("Applying profile values:\n" );
    for (i = 0; i < ptp_num_options; i++)
    {
        printf("  %-18s: %-3d  ranged to {%d to %d}\n", ptp_options[i].name,
                ptp_options[i].default_value, ptp_options[i].min,
                    ptp_options[i].max);
        ptp_write_conf(device, &ptp_options[i],
                ptp_options[i].default_value);
    }
}

void ptp_show_profile(const char *device)
{
    int i, val;

    if (ptp_profile == DEFAULT_PROFILE)
        printf("Default Profile:\n" );
    else if (ptp_profile == TELECOM_PROFILE)
        printf("Telecom Profile:\n" );
    else
        printf("No Profile:\n" );

    for (i = 0; i < ptp_num_options; i++)
    {
        val = ptp_read_conf( device, &ptp_options[i] );
        if (ptp_options[i].type == CONF_TYPE_INT8)
            val = (int8_t)val;
        else if (ptp_options[i].type == CONF_TYPE_INT16)
            val = (int16_t)val;
        else if (ptp_options[i].type == CONF_TYPE_INT32)
            val = (int32_t)val;

        printf("  %-18s: %-3d default: %-3d range: {%d to %d} ", ptp_options[i].name,
                val, ptp_options[i].default_value, ptp_options[i].min,
                ptp_options[i].max);

        if (val < ptp_options[i].min || val > ptp_options[i].max)
            printf("** Warning: out of range.\n");
        else
            printf("\n");

    }
}

static char *ptp_profile_str(int profile)
{
    if (profile == DEFAULT_PROFILE)
        return "default";
    else if (profile == TELECOM_PROFILE)
        return "telecom";
    else
        return "none";
}

void ptp_set_profile(const char *device, int profile)
{
    uint32_t conf;
    exanic_t *exanic;

    exanic = acquire_handle(device);
    conf = exanic_register_read(exanic, REG_PTP_INDEX(REG_PTP_CONF1));
    conf = conf & ~EXANIC_PTP_CONF1_PTP_PROFILE_MASK;
    conf = conf | ((profile << EXANIC_PTP_CONF1_PTP_PROFILE_SHIFT) &
            EXANIC_PTP_CONF1_PTP_PROFILE_MASK);
    exanic_register_write(exanic, REG_PTP_INDEX(REG_PTP_CONF1), conf);
    conf = exanic_register_read(exanic, REG_PTP_INDEX(REG_PTP_CONF1));
    release_handle(exanic);

    ptp_load_profile_defaults(device);
    ptp_apply_profile_defaults(device);

    printf("%s: PTP profile set to %s\n", device, ptp_profile_str(profile));
}

void ptp_set_ptp_enable_state(const char *device, int on)
{
    exanic_t *exanic;
    uint32_t conf;

    exanic = acquire_handle(device);
    conf = exanic_register_read(exanic, REG_PTP_INDEX(REG_PTP_CONF0));
    if (on)
        conf |= EXANIC_PTP_CONF0_PTP_ENABLE;
    else
        conf &= ~EXANIC_PTP_CONF0_PTP_ENABLE;
    exanic_register_write(exanic, REG_PTP_INDEX(REG_PTP_CONF0), conf);
    printf("%s: PTP grandmaster %s\n", device,
            on ? "enabled" : "disabled");
    release_handle(exanic);
}

void ptp_set_ptp_two_step_enable(const char *device, int on)
{
    exanic_t *exanic;
    uint32_t conf;

    exanic = acquire_handle(device);
    conf = exanic_register_read(exanic, REG_PTP_INDEX(REG_PTP_CONF1));
    if (on)
        conf |= EXANIC_PTP_CONF1_PTP_TWO_STEP_EN;
    else
        conf &= ~EXANIC_PTP_CONF1_PTP_TWO_STEP_EN;
    exanic_register_write(exanic, REG_PTP_INDEX(REG_PTP_CONF1), conf);
    printf("%s: PTP clock set to %s mode\n", device,
            on ? "two-step" : "one-step");
    release_handle(exanic);
}

int ptp_command(const char *progname, const char *device,
        int argc, char *argv[])
{
    struct in_addr ipaddr;
    int i, val;

    exanic_t *exanic;
    const char *str;
    exanic_hardware_id_t hw_type;

    exanic = acquire_handle(device);
    hw_type = exanic_get_hw_type(exanic);

    if (!(exanic->hw_info.flags & EXANIC_HW_FLAG_PTP_GM))
    {
        str = exanic_hardware_id_str(hw_type);
        printf("Device %s:\n", device);
        printf("  %s does not support PTP grandmaster functions.\n",
                (str == NULL) ? "unknown" : str);
        return 2;
    }

    /*
     * read the configured profile, then load the profile ptp_options
     * but don't apply over existing values.
     */
    ptp_load_profile_defaults(device);

    if ((argc == 1) && strcmp(argv[0], "status") == 0)
    {
        show_ptp_status(device);
        return 0;
    }
    else if ((argc == 1) && strcmp(argv[0], "enable") == 0)
    {
        ptp_set_ptp_enable_state(device, 1);
        return 0;
    }
    else if ((argc == 1) && strcmp(argv[0], "disable") == 0)
    {
        ptp_set_ptp_enable_state(device, 0);
        return 0;
    }
    else if ((argc == 1) && strcmp(argv[0], "save") == 0)
    {
        return ptp_save_conf(device);
    }
    else if ((argc == 2) && strcmp(argv[0], "ip-address") == 0)
    {
        if (inet_aton(argv[1], &ipaddr) == 0)
            goto ptp_usage_error;
        ptp_set_ip_address(device, &ipaddr);
        return 0;
    }
    else if ((argc == 1) && strcmp(argv[0], "show-profile") == 0)
    {
        ptp_show_profile(device);
        return 0;
    }
    else if ((argc == 2) && strcmp(argv[0], "profile") == 0)
    {
        if (strcmp(argv[1], "default") == 0)
            val = DEFAULT_PROFILE;
        else if (strcmp(argv[1], "telecom") == 0)
            val = TELECOM_PROFILE;
        else if (strcmp(argv[1], "none") == 0)
            val = NO_PROFILE;
        else
            goto ptp_usage_error;
        ptp_set_profile(device, val);
        return 0;
    }
    else if ((argc == 1) && strcmp(argv[0], "one-step") == 0)
    {
        ptp_set_ptp_two_step_enable(device, 0);
        return 0;
    }
    else if ((argc == 1) && strcmp(argv[0], "two-step") == 0)
    {
        ptp_set_ptp_two_step_enable(device, 1);
        return 0;
    }
    else if (argc == 2)
    {
        for (i = 0; i < ptp_num_options; i++)
        {
            if (strcmp(argv[0], ptp_options[i].name) == 0)
            {
                if (ptp_options[i].type == CONF_TYPE_BOOLEAN)
                {
                    if ((val = parse_on_off(argv[1])) == -1)
                        goto ptp_usage_error;
                }
                else
                {
                    if (parse_signed_number(argv[1], &val) == -1)
                        goto ptp_usage_error;
                    if (val < ptp_options[i].min ||
                            val > ptp_options[i].max)
                    {
                        fprintf(stderr, "%s: %s must be in range %d..%d\n",
                                device, ptp_options[i].name,
                                ptp_options[i].min, ptp_options[i].max);
                        exit(1);
                    }
                }
                ptp_write_conf(device, &ptp_options[i], val);
                if (ptp_options[i].type == CONF_TYPE_BOOLEAN)
                    printf("%s: %s %s\n", device, ptp_options[i].name,
                            val ? "enabled" : "disabled");
                else
                    printf("%s: %s set to %d\n", device, ptp_options[i].name,
                            val);
                return 0;
            }
        }
    }

ptp_usage_error:
    fprintf(stderr, "exanic-config version %s\n", EXANIC_VERSION_TEXT);
    fprintf(stderr, "Detailed PTP grandmaster configuration and status:\n");
    fprintf(stderr, "   %s <device> ptp status\n", progname);
    fprintf(stderr, "   %s <device> ptp { enable | disable }\n", progname);
    fprintf(stderr, "   %s <device> ptp ip-address <addr>\n", progname);
    fprintf(stderr, "   %s <device> ptp show-profile\n", progname);
    fprintf(stderr, "   %s <device> ptp profile { default | telecom | none }\n"
            , progname);
    fprintf(stderr, "   %s <device> ptp { one-step | two-step }\n", progname);
    for (i = 0; i < ptp_num_options; i++)
        fprintf(stderr, "   %s <device> ptp %s %s\n", progname,
                ptp_options[i].name,
                (ptp_options[i].type == CONF_TYPE_BOOLEAN) ? "{ on | off }" : "<value>");
    fprintf(stderr, "   %s <device> ptp save\n", progname);
    return 1;
}

/*
 * Glob can be:
 * '*': matches any unsigned integer
 * '[X-Y]': matches unsigned integers X to Y inclusive
 */
int unsigned_integer_matches_glob(uint32_t i, const char* glob)
{
    uint32_t upper, lower, count;

    if (!strcmp(glob, "*"))
        return true;

    if (sscanf(glob, "[%u-%u]%n", &lower, &upper, &count) == 2 && count == strlen(glob))
        return i >= lower && i <= upper;

    if (sscanf(glob, "%u%n", &lower, &count) == 1 && count == strlen(glob))
        return i == lower;

    return false;
}

/*
 * nic is expected to be of the form "exanic0"
 * glob is expected to be of the form "exanic*:[4-7]", etc.
 */
int exanic_port_matches_glob(const char* nic, int port, const char* glob)
{
    uint32_t nic_id;
    char glob1[16], glob2[16];
    size_t glob1len, glob2len;

    if (strncmp(glob, "exanic", 6) != 0)
        return false;
    glob += 6;

    char* split = strchr(glob, ':');
    if (split == NULL)
        return false;

    glob1len = split - glob;
    if (glob1len >= 16)
        return false;
    memcpy(glob1, glob, glob1len);
    glob1[glob1len] = 0;

    glob2len = strlen(split+1);
    if (glob2len >= 16)
        return false;
    memcpy(glob2, split+1, glob2len);
    glob2[glob2len] = 0;

    if (strncmp(nic, "exanic", 6) != 0)
        return false;
    nic += 6;

    nic_id = strtoul(nic, &split, 10);
    if (split == nic)
        return false;

    return unsigned_integer_matches_glob(nic_id, glob1)
        && unsigned_integer_matches_glob(port, glob2);
}

int handle_options_on_nic(char* device, int port_number, int argc, char** argv)
{
    int mode;

    if (argc == 2)
    {
        show_device_info(device, port_number, 0);
        return 0;
    }
    else if (argc == 3 && strcmp(argv[2], "-v") == 0)
    {
        show_device_info(device, port_number, 1);
        return 0;
    }
    else if (argc >= 3 && strcmp(argv[2], "autoneg") == 0 && port_number != -1)
    {
        autoneg_command(argv[0], device, port_number, argc - 3, &argv[3]);
        return 0;
    }
    else if (argc == 4 && strcmp(argv[2], "sfp") == 0
            && strcmp(argv[3], "status") == 0 && port_number != -1)
    {
        show_sfp_status(device, port_number);
        return 0;
    }
    else if (argc == 4 && strcmp(argv[2], "counters") == 0
            && strcmp(argv[3], "reset") == 0 && port_number != -1)
    {
        reset_port_counters(device, port_number);
        return 0;
    }
    else if (argc >= 3 && strcmp(argv[2], "ptp") == 0 && port_number == -1)
    {
        return ptp_command(argv[0], device, argc - 3, &argv[3]);
    }
    else if (argc == 3 && strcmp(argv[2], "up") == 0 && port_number != -1)
    {
        set_port_enable_state(device, port_number, 1);
        return 0;
    }
    else if (argc == 3 && strcmp(argv[2], "down") == 0 && port_number != -1)
    {
        set_port_enable_state(device, port_number, 0);
        return 0;
    }
    else if (argc == 4 && strcmp(argv[2], "bridging") == 0 && port_number == -1)
    {
        if ((mode = parse_on_off(argv[3])) == -1)
            return 1;
        set_ethtool_priv_flags(device, 0, "bridging", mode);
        printf("%s: bridging %s\n", device,
                mode ? "on (ports 0 and 1)" : "off");
        return 0;
    }
    else if (argc == 4 && strcmp(argv[2], "mirror-rx") == 0 &&
            port_number != -1)
    {
        if ((mode = parse_on_off(argv[3])) == -1)
            return 1;
        set_ethtool_priv_flags(device, port_number, "mirror_rx", mode);
        printf("%s:%d: RX mirroring %s\n", device, port_number,
                mode ? "on" : "off");
        return 0;
    }
    else if (argc == 4 && strcmp(argv[2], "mirror-tx") == 0 &&
            port_number != -1)
    {
        if ((mode = parse_on_off(argv[3])) == -1)
            return 1;
        set_ethtool_priv_flags(device, port_number, "mirror_tx", mode);
        printf("%s:%d: TX mirroring %s\n", device, port_number,
                mode ? "on" : "off");
        return 0;
    }
    else if (argc == 4 && strcmp(argv[2], "bypass-only") == 0 &&
            port_number != -1)
    {
        if ((mode = parse_on_off(argv[3])) == -1)
            return 1;
        set_ethtool_priv_flags(device, port_number, "bypass_only", mode);
        printf("%s:%d: bypass-only mode %s, kernel RX and TX %s\n",
                device, port_number, mode ? "on" : "off",
                mode ? "disabled" : "enabled");
        return 0;
    }
    else if (argc == 4 && strcmp(argv[2], "promisc") == 0 &&
            port_number != -1)
    {
        if ((mode = parse_on_off(argv[3])) == -1)
            return 1;

        set_promiscuous_mode(device, port_number, mode);
        return 0;
    }
    else if (argc == 4 && strcmp(argv[2], "speed") == 0 &&
            port_number != -1)
    {
        int speed;
        if (strcmp(argv[3], "auto") == 0)
        {
            /* enable autonegotiation and advertise all supported technologies */
            enable_autoneg(device, port_number, true, 0);
            return 0;
        }
        else
        {
            speed = parse_number(argv[3]);
            if (speed == -1)
                return 1;
        }
        set_speed(device, port_number, speed);
        return 0;
    }
    else if (argc == 4 && strcmp(argv[2], "fec") == 0 &&
            port_number != -1)
    {
        set_fec(device, port_number, argv[3]);
        return 0;
    }
    else if (argc == 4 && strcmp(argv[2], "pps-out") == 0 &&
            port_number == -1)
    {
        if ((mode = parse_on_off(argv[3])) == -1)
            return 1;

        set_per_out(device, 1, mode);
        return 0;
    }
    else if (argc == 4 && strcmp(argv[2], "10m-out") == 0 &&
            port_number == -1)
    {
        if ((mode = parse_on_off(argv[3])) == -1)
            return 1;

        set_per_out(device, 0, mode);
        return 0;
    }
    else if (argc == 4 && strcmp(argv[2], "pps-out-edge-select") == 0 &&
            port_number == -1)
    {
        if ((mode = parse_rising_falling(argv[3])) == -1)
            return 1;
        set_per_out_edge_sel(device, mode);
        return 0;
    }
    else if ((argc == 3 || argc == 4) &&
             (strncmp(argv[2], "rx-", 3) == 0 ||
              strncmp(argv[2], "tx-", 3) == 0) && port_number != -1)
    {
        set_phy_parameter(device, port_number, argv[2], (argc == 4) ? argv[3] : NULL);
        return 0;
    }
    else if (argc == 3 && strcmp(argv[2], "show-phy-param") == 0 &&
                port_number != -1)
    {
        return show_phy_parameters(device, port_number);
    }
    else if (argc == 4 && strcmp(argv[2], "local-loopback") == 0 &&
                port_number != -1)
    {
        if ((mode = parse_on_off(argv[3])) == -1)
            return 1;
        return set_local_loopback(device, port_number, mode);
    }
    else if (argc == 4 && strcmp(argv[2], "disable-tx-padding") == 0 &&
             port_number != -1)
    {
        if ((mode = parse_on_off(argv[3])) == -1)
            return 1;

        return set_disable_tx_padding(device, port_number, mode);
    }
    else if (argc == 4 && strcmp(argv[2], "disable-tx-crc") == 0 &&
             port_number != -1)
    {
        if ((mode = parse_on_off(argv[3])) == -1)
            return 1;

        return set_disable_tx_crc(device, port_number, mode);
    }
    /* below commands for firewall firmware only */
    else if (argc == 4 && strcmp(argv[2], "firewall") == 0
            && port_number == -1)
    {
        if (strcmp(argv[3], "on") == 0)
            set_firewall_state(device, EXANIC_FIREWALL_ENABLE);
        else if (strcmp(argv[3], "off") == 0)
            set_firewall_state(device, EXANIC_FIREWALL_DISABLE);
        else if (strcmp(argv[3], "transparent") == 0)
            set_firewall_state(device, EXANIC_FIREWALL_TRANSPARENT);
        else
            return 1;
        return 0;
    }
    else if (argc == 6 && strcmp(argv[2], "filter") == 0
            && strcmp(argv[3], "add") == 0 && port_number == -1)
    {
        int slot = parse_number(argv[4]);
        if (slot == -1)
            return 1;
        set_firewall_filter(device, slot, argv[5]);
        return 0;
    }
    else if (argc == 5 && strcmp(argv[2], "filter") == 0
            && strcmp(argv[3], "del") == 0 && port_number == -1)
    {
        if (strcmp(argv[4], "all") == 0)
            clear_all_firewall_filters(device);
        else
        {
            int slot = parse_number(argv[4]);
            if (slot == -1)
                return 1;
            clear_firewall_filter(device, slot);
        }
        return 0;
    }
    else if (argc == 4 && strcmp(argv[2], "filter") == 0
            && strcmp(argv[3], "list") == 0 && port_number == -1)
    {
        show_firewall_filters(device);
        return 0;
    }
    else if (argc == 3 && strcmp(argv[2], "firewall-dump") == 0
            && port_number == -1)
    {
        show_firewall_dump(device);
        return 0;
    }

    return 1;
}

int parse_device_glob(char* glob, char devices[][16], int max_devices, int* nmatches)
{
    exanic_port_info_t* info = malloc(sizeof(exanic_port_info_t) * max_devices);
    if ( info == NULL )
    {
        return false;
    }

    ssize_t parsed = exanic_get_all_ports(info, max_devices * sizeof(exanic_port_info_t));
    ssize_t i;

    if (parsed < 0)
    {
        free(info);
        return false;
    }

    *nmatches = 0;
    for (i = 0; i < parsed && i < max_devices; i++)
        if (exanic_port_matches_glob(info[i].device, info[i].port_number, glob))
            sprintf(devices[(*nmatches)++], "%s:%d", info[i].device, info[i].port_number);

    free(info);
    return true;
}

int is_driver_loaded(void)
{
    DIR* handle = opendir(EXANIC_DRIVER_SYSFS_ENTRY);
    if (handle)
    {
        closedir(handle);
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int max_devices = 64;
    char devices[max_devices][16]; /* 16B per device name */
    int ndevices = -1;
    int port_number;
    int i, ret = 0;

    if (!is_driver_loaded())
    {
        fprintf(stderr, "Please load the exanic driver before using this tool\n");
        return 1;
    }

    if (argc < 2 || (argc == 2 && (strcmp(argv[1], "-v") == 0)))
    {
        int verbose = (argc == 2)? 1:0;
        int nnics;
        show_all_devices(verbose, &nnics);
        if (nnics == 0)
        {
            fprintf(stderr, "No ExaNICs detected!\n");
            return 1;
        }
        return 0;
    }

    if (argv[1][0] == '-')
        goto usage_error;

    if (exanic_find_port_by_interface_name(argv[1], devices[0], 16, &port_number) == 0
        || parse_device_port(argv[1], devices[0], &port_number) == 0)
    {
        if (handle_options_on_nic(devices[0], port_number, argc, argv) != 0)
            goto usage_error;

        return 0;
    }
    else if (parse_device_glob(argv[1], devices, max_devices, &ndevices))
    {
        if (ndevices == 0)
        {
            fprintf(stderr, "Found no match for pattern \"%s\". "
                            "Please ensure that this device is plugged in\n", argv[1]);
            return 1;
        }

        for (i = 0; i < ndevices; i++)
        {
            if (parse_device_port(devices[i], devices[i], &port_number) != 0)
                goto usage_error;

            ret |= handle_options_on_nic(devices[i], port_number, argc, argv);
        }

        return ret;
    }

usage_error:
    fprintf(stderr, "exanic-config version %s\n", EXANIC_VERSION_TEXT);
    fprintf(stderr, "Detailed network interface configuration and status:\n");
    fprintf(stderr, "   %s [<device>] [-v]\n", argv[0]);
    fprintf(stderr, "   %s <interface> sfp status\n", argv[0]);
    fprintf(stderr, "   %s <interface> { up | down }\n", argv[0]);
    fprintf(stderr, "   %s <interface> counters reset\n", argv[0]);
    fprintf(stderr, "   %s <device> bridging { on | off }\n", argv[0]);
    fprintf(stderr, "   %s <interface> mirror-rx { on | off }\n", argv[0]);
    fprintf(stderr, "   %s <interface> mirror-tx { on | off }\n", argv[0]);
    fprintf(stderr, "   %s <interface> local-loopback { on | off }\n", argv[0]);
    fprintf(stderr, "   %s <interface> bypass-only { on | off }\n", argv[0]);
    fprintf(stderr, "   %s <interface> promisc { on | off }\n", argv[0]);
    fprintf(stderr, "   %s <interface> speed { 100 | 1000 | 10000 | ... | auto }\n", argv[0]);
    fprintf(stderr, "   %s <interface> autoneg { on | off }\n", argv[0]);
    fprintf(stderr, "   %s <interface> autoneg status [-v]\n", argv[0]);
    fprintf(stderr, "   %s <interface> autoneg restart [-v]\n", argv[0]);
    fprintf(stderr, "   %s <interface> fec { auto | off | rs | baser }\n", argv[0]);
    fprintf(stderr, "   %s <interface> disable-tx-padding { on | off }\n", argv[0]);
    fprintf(stderr, "   %s <interface> disable-tx-crc { on | off }\n", argv[0]);
    fprintf(stderr, "   %s <device> pps-out { on | off }\n", argv[0]);
    fprintf(stderr, "   %s <device> 10m-out { on | off }\n", argv[0]);
    fprintf(stderr, "   %s <device> pps-out-edge-select { rising | falling }\n", argv[0]);
    fprintf(stderr, "   %s <device> ptp <command>\n", argv[0]);
    fprintf(stderr, "      <interface> can be a Linux interface name or ExaNIC device:port (e.g. exanic0:0)\n");
    fprintf(stderr, "      <device> is an ExaNIC device (e.g. exanic0).\n");
    fprintf(stderr, "      Wildcards are accepted for devices and device:ports in the form '*',\n");
    fprintf(stderr, "      which matches anything, or '[X-Y]', which matches numbers X through Y\n");
    fprintf(stderr, "      inclusive, for example \"exanic*:[0-3]\".\n");
    return 2;
}
