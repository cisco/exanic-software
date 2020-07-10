#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include "exanic.h"
#include "config.h"
#include "transceiver.h"

/* QSFP eeprom pages are laid out as follows:
 *
 * 0-127    : lower 00h
 * 128-255  : upper 00h
 * 256-383  : upper 01h
 * 384-511  : upper 02h
 * 512-639  : upper 03h
 *
 * given (i2c) register address and page, the offset into the
 * flat GMODULEEEPROM buffer is computed by adding the page number
 * multiplied by the half-page size (128B) */

#define QSFP_MODULE_EEPROM_OFFSET(page, addr) (addr + (page) * 128)


/* QSFPDD eeprom pages are laid out as follows:
 *
 * 0-127    : lower 00h
 * 128-255  : upper 00h
 * 256-383  : upper 01h
 * 384-511  : upper 10h
 * 512-639  : upper 11h
 *
 * TODO: migrate to new scheme once kernel support for
 *       CMIS connectors is available */

#define QSFPDD_MODULE_EEPROM_OFFSET(p, a)           \
    ({                                              \
        unsigned offset = p == 0 ? a :              \
                          p == 1 ? 128 + a :        \
                          p == 0x10 ? 256 + a :     \
                          384 + a;                  \
        offset;                                     \
     })

#ifndef ETH_MODULE_SFF_8436
#define ETH_MODULE_SFF_8436             0x4
#endif

#ifndef ETH_MODULE_SFF_8436_LEN
#define ETH_MODULE_SFF_8436_LEN         256
#endif

#ifndef ETH_MODULE_SFF_8436_MAX_LEN
#define ETH_MODULE_SFF_8436_MAX_LEN     640
#endif

#ifndef ETH_MODULE_SFF_8636
#define ETH_MODULE_SFF_8636             0x5
#endif

#ifndef ETH_MODULE_SFF_8636_LEN
#define ETH_MODULE_SFF_8636_LEN         ETH_MODULE_SFF_8436_LEN
#endif

#ifndef ETH_MODULE_SFF_8636_MAX_LEN
#define ETH_MODULE_SFF_8636_MAX_LEN     ETH_MODULE_SFF_8436_MAX_LEN
#endif

/* flat memory size for QSFP-DD (lower 00h and upper 00h) */
#define ETH_MODULE_CMIS_QSFPDD_LEN      256
#define ETH_MODULE_CMIS_QSFPDD_MAX_LEN  640

/* convert from big-endian format in eeprom to various data types */
#define OFFSET_TO_U16(data, offset) ((data[offset] << 8)|(data[offset + 1]))
#define OFFSET_TO_S16(data, offset) ((int16_t)OFFSET_TO_U16(data, offset))
/* convert BE 16-bit fixed point to floating point */
#define OFFSET_TO_UFIX16(data, offset) ((double)OFFSET_TO_U16(data, offset) / 256)
#define OFFSET_TO_FLOAT(data, offset)                                           \
    ({                                                                          \
        union { float f; uint32_t i; } u;                                       \
        u.i = ((data[offset] << 24)|(data[offset + 1] << 16)|                   \
               (data[offset + 2] << 8)|(data[offset + 3]));                     \
        u.f;                                                                    \
    })

#define POW(a, b)                                                               \
    ({                                                                          \
        ssize_t r = 1;                                                          \
        for (int i = 0; i < b; ++i) r *= a;                                     \
        r;                                                                      \
    })

/* get module eeprom from kernel */
static struct ethtool_eeprom *
get_module_eeprom(exanic_t *exanic, int port_number, uint32_t *modtype)
{
    struct ethtool_modinfo modinfo;
    char ifname[IF_NAMESIZE];
    struct ethtool_eeprom *eeprom = NULL;
    int err = exanic_get_interface_name(exanic, port_number,
                                        ifname, sizeof ifname);
    if (err)
        return NULL;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        exanic_err_printf("failed to create control socket: %s",
                          strerror(errno));
        return NULL;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strcpy(ifr.ifr_name, ifname);

    /* get module EEPROM length */
    memset(&modinfo, 0, sizeof modinfo);
    modinfo.cmd = ETHTOOL_GMODULEINFO;
    ifr.ifr_data = (void *)&modinfo;

    err = ioctl(fd, SIOCETHTOOL, &ifr);
    if (err == -1)
    {
        exanic_err_printf("ETHTOOL_GMODULEINFO: %s", strerror(errno));
        goto err_sock_close;
    }

    eeprom = calloc(1, sizeof(*eeprom) + modinfo.eeprom_len);
    if (!eeprom)
    {
        exanic_err_printf("failed to allocate module eeprom struct");
        goto err_sock_close;
    }

    eeprom->cmd = ETHTOOL_GMODULEEEPROM;
    eeprom->len = modinfo.eeprom_len;
    eeprom->offset = 0;
    ifr.ifr_data = (void *)eeprom;

    err = ioctl(fd, SIOCETHTOOL, &ifr);
    if (err == -1)
    {
        exanic_err_printf("ETHTOOL_GMODULEINFO: %s", strerror(errno));
        goto err_eeprom_free;
    }

    close(fd);
    *modtype = modinfo.type;
    return eeprom;

err_eeprom_free:
    free(eeprom);
err_sock_close:
    close(fd);
    return NULL;
}

static void exanic_get_xcvr_info_sfp(struct ethtool_eeprom *eep,
                                     exanic_xcvr_info_t *info)
{
    char *data = (char *)eep->data;
    /* see SFP MSA for EEPROM format definition,
     * and see exanic-phyops.c for ethtool interface memory map */

    /* Vendor name: bytes 20-35 */
    strncpy(info->vendor_name, data + 20, 16);

    /* Vendor PN: bytes 40-55 */
    strncpy(info->vendor_pn, data + 40, 16);

    /* Vendor rev: bytes 56-59 */
    strncpy(info->vendor_rev, data + 56, 4);

    /* Vendor SN: bytes 68-83 */
    strncpy(info->vendor_sn, data + 68, 16);

    /* Manufacturing date: bytes 84-91 */
    strncpy(info->date_code, data + 84, 8);

    /* Nominal bit rate (multiple of 100Mbps): byte 12 */
    info->bit_rate = eep->data[12] * 100;

    /* Transceiver compliance byte 5, offset 8 */
    bool copper = eep->data[8] & 0x0C;

    if (copper)
        info->wavelength = 0;
    else
        info->wavelength = OFFSET_TO_U16(eep->data, 60);
}

static void exanic_get_xcvr_info_qsfp(struct ethtool_eeprom *eep,
                                      exanic_xcvr_info_t *info)
{
    char *data = (char *)eep->data;
    /* see SFP MSA for EEPROM format definition,
     * and see exanic-phyops.c for ethtool interface memory map */

    /* Vendor name: bytes 148 to 163 */
    strncpy(info->vendor_name, data + 148, 16);

    /* Vendor PN: bytes 168 to 183 */
    strncpy(info->vendor_pn, data + 168, 16);

    /* Vendor rev: bytes 184 to 185 */
    strncpy(info->vendor_rev, data + 184, 2);

    /* Vendor SN: bytes 196 to 211 */
    strncpy(info->vendor_sn, data + 196, 16);

    /* Manufacturing date: bytes 212 to 219 */
    strncpy(info->date_code, data + 212, 8);

    /* Nominal bit rate (multiple of 100Mbps): byte 140 */
    info->bit_rate = eep->data[140] * 100;

    /* Transmitter tech code */
    uint8_t tech_code = eep->data[147] >> 4;
    bool copper = (tech_code >= 0xa && tech_code <= 0xf);

    if (copper)
        info->wavelength = 0;
    else
        info->wavelength = OFFSET_TO_U16(eep->data, 186) / 20;
}

static void exanic_get_xcvr_info_qsfpdd(struct ethtool_eeprom *eep,
                                        exanic_xcvr_info_t *info)
{
    char *data = (char *)eep->data;
    /* see QSFP-DD MSA for EEPROM format definition,
     * and see exanic-phyops.c for ethtool interface memory map
     * TODO: migrate to new scheme once kernel support for
     *       CMIS connectors is available */

    /* Vendor name: bytes 129 to 144 */
    strncpy(info->vendor_name, data + 129, 16);

    /* Vendor PN: bytes 148 to 163 */
    strncpy(info->vendor_pn, data + 148, 16);

    /* Vendor rev: bytes 164 to 165 */
    strncpy(info->vendor_rev, data + 164, 2);

    /* Vendor SN: bytes 166 to 181 */
    strncpy(info->vendor_sn, data + 166, 16);

    /* Manufacturing date: bytes 182 to 189 */
    strncpy(info->date_code, data + 182, 8);

    /* Media interface tech code */
    uint8_t tech_code = eep->data[212];
    bool copper = (tech_code >= 0xa && tech_code <= 0xf);

    /* If the connector is copper or if upper pages are
     * not available, leave wavelength as 0 and return */
    if (copper || eep->len < ETH_MODULE_CMIS_QSFPDD_MAX_LEN)
    {
        info->wavelength = 0;
        return;
    }

    /* Wavelength, page 01h bytes 138 to 139 */
    size_t wavelength_offset = QSFPDD_MODULE_EEPROM_OFFSET(1, 138);
    info->wavelength = OFFSET_TO_U16(eep->data, wavelength_offset) / 20;
}

int exanic_get_xcvr_info(exanic_t *exanic, int port_number,
                         exanic_xcvr_info_t *info)
{
    uint32_t modtype = 0;
    struct ethtool_eeprom *eeprom =
            get_module_eeprom(exanic, port_number, &modtype);

    if (!eeprom)
        return -1;

    memset(info, 0, sizeof *info);
    switch (modtype)
    {
        case ETH_MODULE_SFF_8079:
        case ETH_MODULE_SFF_8472:
            exanic_get_xcvr_info_sfp(eeprom, info);
            break;
        case ETH_MODULE_SFF_8436:
        case ETH_MODULE_SFF_8636:
            exanic_get_xcvr_info_qsfp(eeprom, info);
            break;
        default:
            exanic_get_xcvr_info_qsfpdd(eeprom, info);
            break;
    }

    free(eeprom);
    return 0;
}

/* return the number of lanes that make up an interface */
static int
exanic_get_interface_width(exanic_t *exanic)
{
    switch (exanic->hw_info.port_ff)
    {
        /* only single-lane interfaces are possible */
        case EXANIC_PORT_SFP:
            return 1;

        /* 40G or 4*10G/1G */
        case EXANIC_PORT_QSFP:
            if (exanic->num_ports == exanic->hw_info.nports)
                return 4;
            return 1;

        /* 2*40G or 8*10G/1G */
        case EXANIC_PORT_QSFPDD:
            if (exanic->num_ports == exanic->hw_info.nports * 2)
                return 4;

            if (exanic->num_ports == exanic->hw_info.nports * 8)
                return 1;

        default: break;
    }

    exanic_err_printf("unsupported connector type (%d) "
                      "or breakout configuration (%d to %d)",
                      exanic->hw_info.port_ff,
                      exanic->hw_info.nports,
                      exanic->num_ports);
    return -1;
}

/* return the starting lane number of interface */
static int
exanic_get_interface_lane_index(exanic_t *exanic, int port, int width)
{
    int phys_width = 0;
    switch (exanic->hw_info.port_ff)
    {
        case EXANIC_PORT_SFP:
            phys_width = 1;
            break;

        case EXANIC_PORT_QSFP:
            phys_width = 4;
            break;

        case EXANIC_PORT_QSFPDD:
            phys_width = 8;
            break;

        default: break;
    }

    if (!phys_width)
    {
        exanic_err_printf("unsupported connector type (%d)",
                          exanic->hw_info.port_ff);
        return -1;
    }

    return (port * width) % phys_width;
}

static int
exanic_get_xcvr_diag_info_sfp(struct ethtool_eeprom *eep,
                              exanic_xcvr_diag_info_t *info)
{
    if (eep->len < ETH_MODULE_SFF_8472_LEN)
    {
        exanic_err_printf("SFP diagnostics page not available");
        return -1;
    }

    /* see SFP MSA for EEPROM page A2h format definition,
     * and see exanic-phyops.c for ethtool interface memory map */
    size_t a2h_off = ETH_MODULE_SFF_8079_LEN;

    /* module temperature slope, offset and raw value */
    int16_t temp = OFFSET_TO_S16(eep->data, a2h_off + 96);
    double temp_slope = OFFSET_TO_UFIX16(eep->data, a2h_off + 84);
    int16_t temp_offset = OFFSET_TO_S16(eep->data, a2h_off + 86);
    info->temp = (double)(temp_slope * temp + temp_offset) / 256;

    /* tx bias current slope, offset and raw value */
    uint16_t txi = OFFSET_TO_U16(eep->data, a2h_off + 100);
    double txi_slope = OFFSET_TO_UFIX16(eep->data, a2h_off + 76);
    int16_t txi_offset = OFFSET_TO_S16(eep->data, a2h_off + 78);
    /* convert from 2 microampere to microampere */
    info->lanes[0].tx_bias = (double)(txi_slope * txi + txi_offset) * 2;

    /* rx power raw value and polynomial terms */
    uint16_t rxp = OFFSET_TO_U16(eep->data, a2h_off + 104);
    double rxp_poly[5] =
    {
        OFFSET_TO_FLOAT(eep->data, a2h_off + 72),
        OFFSET_TO_FLOAT(eep->data, a2h_off + 68),
        OFFSET_TO_FLOAT(eep->data, a2h_off + 64),
        OFFSET_TO_FLOAT(eep->data, a2h_off + 60),
        OFFSET_TO_FLOAT(eep->data, a2h_off + 56),
    };
    /* compute rx power, convert to uw */
    info->lanes[0].rx_power = (rxp_poly[4] * POW(rxp, 4) +
                               rxp_poly[3] * POW(rxp, 3) +
                               rxp_poly[2] * POW(rxp, 2) +
                               rxp_poly[1] * POW(rxp, 1) +
                               rxp_poly[0]) * 0.1;

    /* tx power slope, offset and raw value */
    uint16_t txp = OFFSET_TO_U16(eep->data, a2h_off + 102);
    double txp_slope = OFFSET_TO_UFIX16(eep->data, a2h_off + 80);
    int16_t txp_offset = OFFSET_TO_S16(eep->data, a2h_off + 82);
    /* convert from 0.1 uw to uw */
    info->lanes[0].tx_power = (txp_slope * txp + txp_offset) * 0.1;

    return 0;
}

static int
exanic_get_xcvr_diag_info_qsfp(struct ethtool_eeprom *eep, int lane_start,
                               exanic_xcvr_diag_info_t *info)
{
    /* see QSFP MSA for EEPROM format definition,
     * and see exanic-phyops.c for ethtool interface memory map */

    int16_t temp_raw = OFFSET_TO_S16(eep->data, 22);
    info->temp = (double)temp_raw / 256;

    for (int j = 0, i = lane_start; j < info->num_lanes; ++i, ++j)
    {
        uint16_t rxp = OFFSET_TO_U16(eep->data, 34 + 2 * i);
        uint16_t txp = OFFSET_TO_U16(eep->data, 50 + 2 * i);
        uint16_t txi = OFFSET_TO_U16(eep->data, 42 + 2 * i);

        /* convert from 0.1 uw to uw */
        info->lanes[j].tx_power = txp * 0.1;
        info->lanes[j].rx_power = rxp * 0.1;
        /* 2 ua to ua */
        info->lanes[j].tx_bias = txi * 2;
    }

    return 0;
}

static int
exanic_get_xcvr_diag_info_qsfpdd(struct ethtool_eeprom *eep, int lane_start,
                                 exanic_xcvr_diag_info_t *info)
{
    if (eep->len < ETH_MODULE_CMIS_QSFPDD_MAX_LEN)
    {
        exanic_err_printf("QSFP-DD diagnostics pages not available");
        return -1;
    }

    /* see QSFP-DD MSA for EEPROM format definition,
     * and see exanic-phyops.c for ethtool interface memory map
     * TODO: migrate to new scheme once kernel support for
     *       CMIS connectors is available */

    int16_t temp_raw = OFFSET_TO_S16(eep->data, 14);
    info->temp = (double)temp_raw / 256;

    for (int j = 0, i = lane_start; j < info->num_lanes; ++i, ++j)
    {
        uint16_t rxp = OFFSET_TO_U16(eep->data,
                                     QSFPDD_MODULE_EEPROM_OFFSET(0x11, 186) + 2 * i);
        uint16_t txi = OFFSET_TO_U16(eep->data,
                                     QSFPDD_MODULE_EEPROM_OFFSET(0x11, 170) + 2 * i);
        uint16_t txp = OFFSET_TO_U16(eep->data,
                                     QSFPDD_MODULE_EEPROM_OFFSET(0x11, 154) + 2 * i);

        /* convert from 0.1 uw to uw */
        info->lanes[j].tx_power = txp * 0.1;
        info->lanes[j].rx_power = rxp * 0.1;
        /* 2 ua to ua */
        info->lanes[j].tx_bias = txi * 2;
    }

    return 0;
}

int exanic_get_xcvr_diag_info(exanic_t *exanic, int port_number,
                              exanic_xcvr_diag_info_t **info)
{
    int err = 0;

    /* get the width and lane index of the interface */
    int width = exanic_get_interface_width(exanic);
    if (width == -1)
    {
        err = -1;
        goto unset_info;
    }

    int lane = exanic_get_interface_lane_index(exanic, port_number, width);
    if (lane == -1)
    {
        err = -1;
        goto unset_info;
    }

    /* dump module eeprom from driver */
    uint32_t modtype = 0;
    struct ethtool_eeprom *eeprom =
           get_module_eeprom(exanic, port_number, &modtype);
    if (!eeprom)
    {
        err = -1;
        goto unset_info;
    }

    /* allocate exanic_xcvr_diag_info_t structure with enough space
     * at the end to hold diag info for all lanes that make up this port */
    *info = calloc(1, sizeof(exanic_xcvr_diag_info_t) +
                      sizeof(struct exanic_port_xcvr_diag) * width);
    if (!*info)
    {
        err = -1;
        exanic_err_printf("failed to allocate diag info structure");
        goto free_eeprom;
    }
    (**info).num_lanes = width;

    switch (modtype)
    {
        case ETH_MODULE_SFF_8079:
        case ETH_MODULE_SFF_8472:
            err = exanic_get_xcvr_diag_info_sfp(eeprom, *info);
            break;
        case ETH_MODULE_SFF_8436:
        case ETH_MODULE_SFF_8636:
            err = exanic_get_xcvr_diag_info_qsfp(eeprom, lane, *info);
            break;
        default:
            err = exanic_get_xcvr_diag_info_qsfpdd(eeprom, lane, *info);
            break;
    }

    if (err)
        goto free_info;

    free(eeprom);
    return 0;

free_info:
    free(*info);
free_eeprom:
    free(eeprom);
unset_info:
    *info = NULL;
    return err;
}
