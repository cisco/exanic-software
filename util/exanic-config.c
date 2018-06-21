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
#ifndef ETHTOOL_GET_TS_INFO
#include "ethtool_ts_info.h"
#endif
#ifndef SPEED_40000
#define SPEED_40000 40000
#endif

#include <exanic/port.h>
#include <exanic/util.h>
#include <exanic/exanic.h>
#include <exanic/config.h>
#include <exanic/register.h>
#include <exanic/sfp.h>
#include <exanic/firewall.h>
#include <exanic/x4/i2c.h>

enum conf_option_types {
    CONF_TYPE_BOOLEAN,
    CONF_TYPE_INT8,
    CONF_TYPE_UINT8,
    CONF_TYPE_INT16,
    CONF_TYPE_UINT16,
    CONF_TYPE_INT32,
    CONF_TYPE_UINT32
};

#define SERIAL_ADDRESS  0x00
#define SERIAL_LEN      6

#define CLOCKFD 3
#define FD_TO_CLOCKID(fd) ((~(clockid_t)(fd) << 3) | CLOCKFD)

int exanic_i2c_eeprom_read( exanic_t *exanic, uint8_t regaddr, char *buffer,
        size_t size )
{
    switch( exanic_get_hw_type(exanic))
    {
        case EXANIC_HW_X2:
        case EXANIC_HW_X10:
        case EXANIC_HW_X10_GM:
        case EXANIC_HW_X10_HPT:
        case EXANIC_HW_X40:
        case EXANIC_HW_V5P:
            return exanic_x2_i2c_eeprom_read(exanic, regaddr, buffer, size );
        case EXANIC_HW_X4:
            return exanic_x4_i2c_eeprom_read(exanic, regaddr, buffer, size );
        default:
            return -1;
    }
}

int parse_number(const char *str)
{
    char *p;
    int num = strtol(str, &p, 0);
    if (*p != '\0')
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

int ethtool_ioctl(int fd, char *ifname, void *data)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
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

int get_local_loopback(exanic_t *exanic, int port_number)
{
    exanic_hardware_id_t hw_type = exanic_get_hw_type(exanic);
    int loopback;

    if ((hw_type == EXANIC_HW_X4) || (hw_type == EXANIC_HW_X2))
    {
        char buf;
        uint8_t reg_addr = 0x0A;

        int port_status = exanic_get_port_status(exanic, port_number);
        if (!(port_status & EXANIC_PORT_STATUS_ENABLED))
            return -1;

        if (exanic_x4_i2c_phy_read(exanic, port_number, reg_addr, &buf, 1) != 0)
            return -1;

        loopback = (buf & 0x40) ? 0 : 1;
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

void show_device_info(const char *device, int port_number, int verbose)
{
    int i, first_port, last_port, port_status;
    const char *str;
    exanic_t *exanic;
    exanic_hardware_id_t hw_type;
    exanic_function_id_t function;
    time_t rev_date;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    exanic = acquire_handle(device);
    hw_type = exanic_get_hw_type(exanic);
    function = exanic_get_function_id(exanic);
    rev_date = exanic_get_hw_rev_date(exanic);

    printf("Device %s:\n", device);

    str = exanic_hardware_id_str(hw_type);
    printf("  Hardware type: %s\n", (str == NULL) ? "unknown" : str);

    if (verbose)
    {
        uint8_t serial[SERIAL_LEN] = {0};
        if (exanic_i2c_eeprom_read (exanic, SERIAL_ADDRESS, (char*) serial,
                                    SERIAL_LEN) == -1)
        {
            fprintf (stderr, "%s: %s\n", device, exanic_get_last_error ());
        }
        else
        {
            printf ("  Serial number: ");
            int i = 0;
            for (i = 0; i < SERIAL_LEN; i++)
                printf ("%02X", serial[i]);
             printf ("\n");
        }
    }


    if (hw_type == EXANIC_HW_Z1 || hw_type == EXANIC_HW_Z10 ||
        hw_type == EXANIC_HW_X4 || hw_type == EXANIC_HW_X2 ||
        hw_type == EXANIC_HW_X10 || hw_type == EXANIC_HW_X10_GM ||
        hw_type == EXANIC_HW_X40  || hw_type == EXANIC_HW_X10_HPT ||
        hw_type == EXANIC_HW_V5P)
    {
        uint32_t temp, vccint, vccaux;
        double temp_real=0, vccint_real=0, vccaux_real=0;

        temp = exanic_register_read(exanic, REG_HW_INDEX(REG_HW_TEMPERATURE));
        vccint = exanic_register_read(exanic, REG_HW_INDEX(REG_HW_VCCINT));
        vccaux = exanic_register_read(exanic, REG_HW_INDEX(REG_HW_VCCAUX));

        if (hw_type == EXANIC_HW_Z1 || hw_type == EXANIC_HW_Z10)
        {
            temp_real = temp * (503.975 / 1024.0) - 273.15;
            vccint_real = vccint * 3.0 / 1024.0;
            vccaux_real = vccaux * 3.0 / 1024.0;
        }
        else if (hw_type == EXANIC_HW_X4 || hw_type == EXANIC_HW_X2 ||
                    hw_type == EXANIC_HW_X10 || hw_type == EXANIC_HW_X10_GM ||
                    hw_type == EXANIC_HW_X40 || hw_type == EXANIC_HW_X10_HPT)
        {
            temp_real = temp * (503.975 / 4096.0) - 273.15;
            vccint_real = vccint * 3.0 / 4096.0;
            vccaux_real = vccaux * 3.0 / 4096.0;
        }
        else if (hw_type == EXANIC_HW_V5P)
        {
            temp_real = temp * (509.314 / 4096.0) - 280.231;
            vccint_real = vccint * 3.0 / 4096.0;
            vccaux_real = vccaux * 3.0 / 4096.0;
        }

        printf("  Temperature: %.1f C   VCCint: %.2f V   VCCaux: %.2f V\n",
                temp_real, vccint_real, vccaux_real);
    }

    if (hw_type == EXANIC_HW_X4 || hw_type == EXANIC_HW_X2 || hw_type == EXANIC_HW_V5P)
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
        asctime_r(tm, buf);
        if ((p = strchr(buf, '\n')) != NULL)
            *p = '\0';

        printf("  Firmware date: %04d%02d%02d (%s)\n", tm->tm_year + 1900,
                tm->tm_mon + 1, tm->tm_mday, buf);
    }

    if (function == EXANIC_FUNCTION_DEVKIT)
    {
        unsigned user_version;
        user_version = exanic_register_read(exanic,
                        REG_EXANIC_INDEX(REG_EXANIC_DEVKIT_USER_VERSION));
        printf("  Customer version: %u (%x)\n", user_version, user_version);
    }

    if (hw_type == EXANIC_HW_V5P)
    {
        uint32_t ext_pwr = exanic_register_read(exanic,
                    REG_HW_INDEX(REG_HW_MISC_GPIO));
        printf("  External 12V power: %s\n", ext_pwr ? "detected" : "not detected");
    }

    if (function == EXANIC_FUNCTION_NIC ||
            function == EXANIC_FUNCTION_PTP_GM)
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
        uint32_t caps = exanic_get_caps(exanic);
        if (caps & EXANIC_CAP_BRIDGING ||
            hw_type == EXANIC_HW_Z1 || hw_type == EXANIC_HW_Z10 ||
            hw_type == EXANIC_HW_X4 || hw_type == EXANIC_HW_X2)
        {
            uint32_t pl_cfg = exanic_get_bridging_config(exanic);
            printf("  Bridging: %s\n", (pl_cfg & EXANIC_FEATURE_BRIDGE) ?
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
        if ((hw_type == EXANIC_HW_X40) || (hw_type == EXANIC_HW_V5P))
        {
            /* No signal detected pin on QSFP. */
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
            exanic_port_mirror_supported(exanic, i) &&
            (rx_usable || tx_usable))
        {
            uint32_t pl_cfg;
            uint32_t rx_bit = 0, tx_bit = 0;

            pl_cfg = exanic_get_bridging_config(exanic);

            switch (i)
            {
                case 0:
                    rx_bit = EXANIC_FEATURE_MIRROR_RX_0;
                    tx_bit = EXANIC_FEATURE_MIRROR_TX_0;
                    break;
                case 1:
                    rx_bit = EXANIC_FEATURE_MIRROR_RX_1;
                    tx_bit = EXANIC_FEATURE_MIRROR_TX_1;
                    break;
                case 2:
                    rx_bit = EXANIC_FEATURE_MIRROR_RX_2;
                    tx_bit = EXANIC_FEATURE_MIRROR_TX_2;
                    break;
            }

            printf("    Mirroring: %s\n",
                    (pl_cfg & rx_bit) && (pl_cfg & tx_bit) ? "RX and TX" :
                    (pl_cfg & rx_bit) ? "RX only" :
                    (pl_cfg & tx_bit) ? "TX only" : "off");
        }

        if ((function == EXANIC_FUNCTION_NIC ||
               function == EXANIC_FUNCTION_PTP_GM ||
                 function == EXANIC_FUNCTION_DEVKIT)
                    && rx_usable)
        {
            int loopback, promisc;

            if (hw_type == EXANIC_HW_X4 || hw_type == EXANIC_HW_X2 ||
                    hw_type == EXANIC_HW_X10 || hw_type == EXANIC_HW_X10_GM ||
                    hw_type == EXANIC_HW_X40 || hw_type == EXANIC_HW_X10_HPT ||
                    hw_type == EXANIC_HW_V5P)
            {
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
            }
            promisc = exanic_get_promiscuous_mode(exanic, i);
            if ((promisc != -1) && (promisc || verbose))
                printf("    Promiscuous mode: %s\n", promisc ? "on" : "off");
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
}

void show_all_devices(int verbose)
{
    DIR *d;
    struct dirent *dir;
    char exanic_file[32];
    int exanic_num;
    int prev_num = -1;
    int num;

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
        }
    }
    while (exanic_num < INT_MAX);
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
    int channel;
    exanic_t *exanic;
    exanic_sfp_info_t sfp_info;
    exanic_sfp_diag_info_t sfp_diag_info;
    exanic_qsfp_info_t qsfp_info;
    exanic_qsfp_diag_info_t qsfp_diag_info;
    exanic_hardware_id_t hw_type;


    exanic = acquire_handle(device);
    port_status = exanic_get_port_status(exanic, port_number);
    hw_type = exanic_get_hw_type(exanic);

    if ((port_status & EXANIC_PORT_STATUS_SFP) == 0)
    {
        fprintf(stderr, "%s:%d: SFP not present\n", device, port_number);
        release_handle(exanic);
        return 1;
    }

    if (hw_type == EXANIC_HW_X40 || hw_type == EXANIC_HW_V5P)
    {
        printf("Device %s port %d QSFP module %d status:\n", device,
                    port_number, port_number/4);

        if (exanic_get_qsfp_info(exanic, port_number, &qsfp_info) == 0)
        {
            printf("  Vendor: %16.16s PN: %16.16s  rev: %4.4s\n",
                   qsfp_info.vendor_name, qsfp_info.vendor_pn,
                    qsfp_info.vendor_rev);
            printf("                           SN: %16.16s date: %8.8s\n",
                    qsfp_info.vendor_sn, qsfp_info.date_code);

            printf("  Wavelength: %d nm\n", qsfp_info.wavelength);
            printf("  Nominal bit rate: %d Mbps\n", qsfp_info.bit_rate);
        }
        else
        {
            printf("  SFP EEPROM not available\n");
        }

        if (exanic_get_qsfp_diag_info(exanic, port_number, &qsfp_diag_info)
                    == 0)
        {
            for (channel = 0; channel < 4; channel++)
            {
                printf("  Channel %d Rx power: %.1f dBm (%.2f mW)\n", channel,
                        log10(qsfp_diag_info.rx_power[channel]) * 10,
                            qsfp_diag_info.rx_power[channel]);
                printf("             Tx bias: %.2f mA\n",
                            qsfp_diag_info.tx_bias[channel]);
            }
            printf("  Temperature: %.1f C\n", qsfp_diag_info.temp);
        }
        else
        {
            printf("  SFP diagnostics not available\n");
        }
    }
    else
    {
        printf("Device %s port %d SFP status:\n", device, port_number);

        if (exanic_get_sfp_info(exanic, port_number, &sfp_info) == 0)
        {
            printf("  Vendor: %16.16s PN: %16.16s  rev: %4.4s\n",
                   sfp_info.vendor_name, sfp_info.vendor_pn,
                    sfp_info.vendor_rev);
            printf("                           SN: %16.16s date: %8.8s\n",
                    sfp_info.vendor_sn, sfp_info.date_code);

            printf("  Wavelength: %d nm\n", sfp_info.wavelength);
            printf("  Nominal bit rate: %d Mbps\n", sfp_info.bit_rate);
        }
        else
        {
            printf("  SFP EEPROM not available\n");
        }

        if (exanic_get_sfp_diag_info(exanic, port_number, &sfp_diag_info) == 0)
        {
            printf("  Rx power: %.1f dBm (%.2f mW)\n",
                    log10(sfp_diag_info.rx_power) * 10, sfp_diag_info.rx_power);
            printf("  Tx power: %.1f dBm (%.2f mW)\n",
                    log10(sfp_diag_info.tx_power) * 10, sfp_diag_info.tx_power);
            printf("  Temperature: %.1f C\n", sfp_diag_info.temp);
        }
        else
        {
            printf("  SFP diagnostics not available\n");
        }
    }

    release_handle(exanic);
    return 0;
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
        exit(1);
    }

    if (mode)
        ifr.ifr_flags |= IFF_UP;
    else
        ifr.ifr_flags &= ~IFF_UP;

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }

    printf("%s:%d: port %s\n", device, port_number,
            mode ? "enabled" : "disabled");
}

void set_promiscuous_mode(const char *device, int port_number, int mode)
{
    struct ifreq ifr;
    int fd;

    get_interface_name(device, port_number, ifr.ifr_name, IFNAMSIZ);

    /* Enable promisc mode via socket ioctls */
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ||
        ioctl(fd, SIOCGIFFLAGS, &ifr) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }

    if (mode)
        ifr.ifr_flags |= IFF_PROMISC;
    else
        ifr.ifr_flags &= ~IFF_PROMISC;

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }

    printf("%s:%d: promiscuous mode %s\n", device, port_number,
            mode ? "enabled" : "disabled");
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

    if ((speed != SPEED_100) && (speed != SPEED_1000) &&
        (speed != SPEED_10000) && (speed != SPEED_40000))
    {
        fprintf(stderr, "%s:%d: Invalid speed requested\n", device, port_number);
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
        exit(1);
    }

    sprintf(phc_device, "/dev/ptp%d", phc_index);
    if ((clkfd = open(phc_device, O_RDWR)) == -1)
    {
        fprintf(stderr, "%s: %s\n", device, strerror(errno));
        exit(1);
    }
    if (clock_gettime(FD_TO_CLOCKID(clkfd), &ts) == -1)
    {
        fprintf(stderr, "%s: %s\n", device, strerror(errno));
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
        exit(1);
    }

    printf("%s: %s output %s\n", device, pps_10m ? "PPS" : "10M",
            enable ? "enabled" : "disabled");
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
        char buf;
        uint8_t reg_addr = 0x0A;

        int port_status = exanic_get_port_status(exanic, port_number);
        if (!(port_status & EXANIC_PORT_STATUS_ENABLED))
        {
            fprintf(stderr, "%s:%d: cannot enable loopback on disabled port\n", device, port_number);
            goto out;
        }

        if (exanic_x4_i2c_phy_read(exanic, port_number, reg_addr, &buf, 1) != 0)
        {
            fprintf(stderr, "%s:%d: error reading from PHY\n", device, port_number);
            goto out;
        }

        buf = enable ? buf & (~0x40) : buf | 0x40;
        if (exanic_x4_i2c_phy_write(exanic, port_number, reg_addr, &buf, 1) != 0)
        {
            fprintf(stderr, "%s:%d: error writing to PHY\n", device, port_number);
            goto out;
        }
    }
    else
    {
        uint32_t flags;
        flags = exanic_register_read(exanic, REG_PORT_INDEX(port_number,
                                     REG_PORT_FLAGS));
        if (enable)
            flags = flags | EXANIC_PORT_FLAG_LOOPBACK;
        else
            flags = flags & (~EXANIC_PORT_FLAG_LOOPBACK);

        exanic_register_write(exanic, REG_PORT_INDEX(port_number, REG_PORT_FLAGS), flags);
    }

    loopback = get_local_loopback(exanic, port_number);
    if ((loopback == -1) || (enable && !loopback) || (!enable && loopback))
    {
        fprintf(stderr, "%s:%d: failed to update loopback mode: not supported by firmware?\n", device, port_number);
        goto out;
    }

    printf("%s:%d: local-loopback mode %s\n", device, port_number,
            enable ? "enabled" : "disabled");
    release_handle(exanic);
    return 0;

out:
    release_handle(exanic);
    return 1;
}

static const struct phy_parameter {
    const char *name;
    uint8_t reg_addr;
    uint8_t mask;
} phy_parameters[] = {
    { "rx-gain",        0x10, 0x7f },
    { "rx-preemphasis", 0x11, 0x1f },
    { "rx-offset",      0x12, 0xff },
    { "tx-gain",        0x16, 0x07 },
    { "tx-preemphasis", 0x17, 0x1f },
    { "tx-slewrate",    0x18, 0x07 }
};

void set_phy_parameter(const char *device, int port_number,
                       const char *parameter_name, const char *value_string)
{
    exanic_t *exanic = acquire_handle(device);
    uint8_t reg_addr = 0;
    uint8_t mask = 0;
    char buf;
    int i;

    for (i = 0; i < sizeof(phy_parameters)/sizeof(struct phy_parameter); i++)
    {
        if (strcmp(parameter_name, phy_parameters[i].name) == 0)
        {
            reg_addr = phy_parameters[i].reg_addr;
            mask = phy_parameters[i].mask;
        }
    }

    if (!mask)
    {
        fprintf(stderr, "%s:%d: invalid parameter name %s\n", device,
                port_number, parameter_name);
        goto out;
    }

    if (value_string)
    {
        int value = parse_number(value_string);
        if ((value < 0) || (value > mask))
        {
            fprintf(stderr, "%s:%d: invalid value specified for %s\n", device,
                    port_number, parameter_name);
            goto out;
        }

        buf = value;
        if (exanic_x4_i2c_phy_write(exanic, port_number, reg_addr, &buf, 1) != 0)
        {
            fprintf(stderr, "%s:%d: error writing to PHY\n", device, port_number);
            goto out;
        }
    }
    else
    {
        if (exanic_x4_i2c_phy_read(exanic, port_number, reg_addr, &buf, 1) != 0)
        {
            fprintf(stderr, "%s:%d: error reading from PHY\n", device, port_number);
            goto out;
        }
    }
    printf("%s:%d: %s = %u (range 0..%u)\n", device, port_number,
                                                  parameter_name, buf, mask);
out:
    release_handle(exanic);
}

void show_phy_parameters(const char *device, int port_number)
{
    exanic_t *exanic = acquire_handle(device);
    const char *parameter_name;
    uint8_t reg_addr;
    uint8_t mask;
    char buf;
    int i;

    for (i = 0; i < sizeof(phy_parameters)/sizeof(struct phy_parameter); i++)
    {
        parameter_name = phy_parameters[i].name;
        reg_addr = phy_parameters[i].reg_addr;
        mask = phy_parameters[i].mask;
        if (exanic_x4_i2c_phy_read(exanic, port_number, reg_addr, &buf, 1) != 0)
        {
            fprintf(stderr, "%s:%d: error reading from PHY\n", device, port_number);
            break;
        }

        printf("%s:%d: %s = %u (range 0..%u)\n", device, port_number,
                                                  parameter_name, buf, mask);
    }
    release_handle(exanic);
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
        utc_time.tv_sec = hw_time.tv_sec - tai_offset;
        utc_time.tv_nsec = hw_time.tv_nsec;
        strftime(buffer, sizeof(buffer), "%F %T", gmtime(&hw_time.tv_sec));
        printf("  Hardware time: %s.%09ld TAI\n", buffer, hw_time.tv_nsec);
        strftime(buffer, sizeof(buffer), "%F %T", gmtime(&utc_time.tv_sec));
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

void ptp_save_conf(const char *device)
{
    exanic_t *exanic;
    int i, j;
    uint32_t reg;
    unsigned char buffer[4];
    int addresses[] = { 0x20, 0x24, 0x28, 0x2C };
    int registers[] = { REG_PTP_IP_ADDR, REG_PTP_CONF0,
                        REG_PTP_CONF1, REG_PTP_CONF2 };

    exanic = acquire_handle(device);

    for (i = 0; i < sizeof(addresses)/sizeof(int); i++)
    {
        reg = exanic_register_read(exanic, REG_PTP_INDEX(registers[i]));
        memcpy(buffer, (char*)&reg, sizeof(uint32_t));

        for (j=0; j < sizeof(uint32_t); j++)
        {
            if (exanic_x2_i2c_eeprom_write(exanic, addresses[i] + j,
                    (char *)buffer + j, 1) == -1)
            {
                fprintf(stderr, "%s: error saving PTP configuration: %s\n",
                        device, exanic_get_last_error());
                release_handle(exanic);
                exit(1);
            }
        }
    }

    printf("%s: PTP configuration saved to EEPROM\n", device);
    release_handle(exanic);
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

    if (hw_type != EXANIC_HW_X10_GM)
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
        ptp_save_conf(device);
        return 0;
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
    fprintf(stderr, "exanic-config version 2.1.1-git\n");
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
    else if (argc == 4 && strcmp(argv[2], "sfp") == 0
            && strcmp(argv[3], "status") == 0 && port_number != -1)
    {
        return show_sfp_status(device, port_number);
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
        int speed = parse_number(argv[3]);
        if (speed == -1)
            return 1;

        set_speed(device, port_number, speed);
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
        show_phy_parameters(device, port_number);
        return 0;
    }
    else if (argc == 4 && strcmp(argv[2], "local-loopback") == 0 &&
                port_number != -1)
    {
        if ((mode = parse_on_off(argv[3])) == -1)
            return 1;
        return set_local_loopback(device, port_number, mode);
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

int main(int argc, char *argv[])
{
    int max_devices = 64;
    char devices[max_devices][16]; /* 16B per device name */
    int ndevices = -1;
    int port_number;
    int i, ret = 0;

    if (argc < 2)
    {
        show_all_devices(0);
        return 0;
    }
    else if (argc == 2 && strcmp(argv[1], "-v") == 0)
    {
        show_all_devices(1);
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
            return 1;

        for (i = 0; i < ndevices; i++)
        {
            if (parse_device_port(devices[i], devices[i], &port_number) != 0)
                goto usage_error;

            ret |= handle_options_on_nic(devices[i], port_number, argc, argv);
        }

        return ret;
    }

usage_error:
    fprintf(stderr, "exanic-config version 2.1.1-git\n");
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
    fprintf(stderr, "   %s <interface> speed <speed>\n", argv[0]);
    fprintf(stderr, "   %s <device> pps-out { on | off }\n", argv[0]);
    fprintf(stderr, "   %s <device> 10m-out { on | off }\n", argv[0]);
    fprintf(stderr, "   %s <device> pps-out-edge-select { rising | falling }\n", argv[0]);
    fprintf(stderr, "   %s <device> ptp <command>\n", argv[0]);
    fprintf(stderr, "      <interface> can be a Linux interface name or ExaNIC device:port (e.g. exanic0:0)\n");
    fprintf(stderr, "      <device> is an ExaNIC device (e.g. exanic0).\n");
    fprintf(stderr, "      Wildcards are accepted for devices and device:ports in the form '*',\n");
    fprintf(stderr, "      which matches anything, or '[X-Y]', which matches numbers X through Y\n");
    fprintf(stderr, "      inclusive, for example \"exanic*:[0-3]\".\n");
    fprintf(stderr, "      <speed> is in Mbit/s (e.g. 100 | 1000 | 10000 | 40000)\n");
    return 2;
}
