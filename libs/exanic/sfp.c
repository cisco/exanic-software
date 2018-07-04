#include <string.h>

#include "exanic.h"
#include "pcie_if.h"
#include "port.h"
#include "util.h"
#include "z1/i2c.h"
#include "z10/i2c.h"
#include "x4/i2c.h"
#include "sfp.h"

static int sfp_read(exanic_t *exanic, int port_number, int devaddr, int regaddr,
                    char *buf, size_t size)
{
    switch (exanic_get_hw_type(exanic))
    {
        case EXANIC_HW_Z1:
            return z1_i2c_sfp_read(exanic, port_number, devaddr, regaddr,
                    buf, size);
        case EXANIC_HW_Z10:
            return z10_i2c_sfp_read(exanic, port_number, devaddr, regaddr,
                    buf, size);
        case EXANIC_HW_X4:
        case EXANIC_HW_X2:
        case EXANIC_HW_X10:
        case EXANIC_HW_X10_GM:
        case EXANIC_HW_X10_HPT:
        case EXANIC_HW_X25:
            return exanic_x4_x2_i2c_sfp_read(exanic, port_number, devaddr, regaddr,
                    buf, size);
        case EXANIC_HW_X40:
        case EXANIC_HW_V5P:
            return exanic_x40_i2c_sfp_read(exanic, port_number, devaddr, regaddr,
                    buf, size);
        default:
            exanic_err_printf("not implemented for this hardware");
            return -1;
    }
}

int exanic_get_sfp_info(exanic_t *exanic, int port_number,
                        exanic_sfp_info_t *info)
{
    uint8_t data[2];

    if (port_number < 0 || port_number >= exanic->num_ports)
    {
        exanic_err_printf("invalid port number: %d", port_number);
        return -1;
    }

    /* see SFP MSA for EEPROM format definition */

    /* Vendor name: byte 20-35 */
    if (sfp_read(exanic, port_number, 0xA0, 20, info->vendor_name, 16) == -1)
        return -1;
    info->vendor_name[16] = '\0';

    /* Vendor PN: byte 40-55 */
    if (sfp_read(exanic, port_number, 0xA0, 40, info->vendor_pn, 16) == -1)
        return -1;
    info->vendor_pn[16] = '\0';

    /* Vendor rev: byte 56-59 */
    if (sfp_read(exanic, port_number, 0xA0, 56, info->vendor_rev, 4) == -1)
        return -1;
    info->vendor_rev[4] = '\0';

    /* Vendor SN: byte 68-83 */
    if (sfp_read(exanic, port_number, 0xA0, 68, info->vendor_sn, 16) == -1)
        return -1;
    info->vendor_sn[16] = '\0';

    /* Manufacturing date: byte 84-91 */
    if (sfp_read(exanic, port_number, 0xA0, 84, info->date_code, 8) == -1)
        return -1;
    info->date_code[8] = '\0';

    /* Wavelength: byte 60-61 */
    if (sfp_read(exanic, port_number, 0xA0, 60, (char *)data, 2) == -1)
        return -1;
    info->wavelength = data[1] | (data[0] << 8);

    /* Nominal bit rate (multiple of 100Mbps): byte 12 */
    if (sfp_read(exanic, port_number, 0xA0, 12, (char *)data, 1) == -1)
        return -1;
    info->bit_rate = data[0] * 100;

    return 0;
}

int exanic_get_qsfp_info(exanic_t *exanic, int port_number,
                        exanic_qsfp_info_t *info)
{
    uint8_t data[2];

    if (port_number < 0 || port_number >= exanic->num_ports)
    {
        exanic_err_printf("invalid port number: %d", port_number);
        return -1;
    }

    /* see SFP MSA for EEPROM format definition */

    /* Vendor name: byte 148, length 16 */
    if (sfp_read(exanic, port_number, 0xA0, 148, info->vendor_name, 16) == -1)
        return -1;
    info->vendor_name[16] = '\0';

    /* Vendor PN: byte 168, length 16 */
    if (sfp_read(exanic, port_number, 0xA0, 168, info->vendor_pn, 16) == -1)
        return -1;
    info->vendor_pn[16] = '\0';

    /* Vendor rev: byte 184 length 2 */
    if (sfp_read(exanic, port_number, 0xA0, 184, info->vendor_rev, 2) == -1)
        return -1;
    info->vendor_rev[2] = '\0';

    /* Vendor SN: byte 196 length 16 */
    if (sfp_read(exanic, port_number, 0xA0, 196, info->vendor_sn, 16) == -1)
        return -1;
    info->vendor_sn[16] = '\0';

    /* Manufacturing date: byte 212 length 8 */
    if (sfp_read(exanic, port_number, 0xA0, 212, info->date_code, 8) == -1)
        return -1;
    info->date_code[8] = '\0';

    /* Wavelength: byte 186 length 2 */
    if (sfp_read(exanic, port_number, 0xA0, 186, (char *)data, 2) == -1)
        return -1;
    info->wavelength = data[1] | (data[0] << 8);
    info->wavelength = info->wavelength / 20;

    /* Nominal bit rate (multiple of 100Mbps): byte 140 length 1 */
    if (sfp_read(exanic, port_number, 0xA0, 140, (char *)data, 1) == -1)
        return -1;
    info->bit_rate = data[0] * 100;

    return 0;
}

static int sfp_read_float(exanic_t *exanic, int port_number, int devaddr,
                          int regaddr, float *val)
{
    char raw_buf[4];
    union {
        char c[4];
        float f;
    } buf;

    if (sfp_read(exanic, port_number, devaddr, regaddr, raw_buf, 4) == -1)
        return -1;

    /* Convert from big-endian to little-endian */
    buf.c[3] = raw_buf[0]; buf.c[2] = raw_buf[1];
    buf.c[1] = raw_buf[2]; buf.c[0] = raw_buf[3];

    *val = buf.f;
    return 0;
}

static int sfp_read_short(exanic_t *exanic, int port_number, int devaddr,
                          int regaddr, uint16_t *val)
{
    uint8_t buf[2];

    if (sfp_read(exanic, port_number, devaddr, regaddr, (char *)buf, 2) == -1)
        return -1;

    *val = (buf[0] << 8) | buf[1];
    return 8;
}

int exanic_get_sfp_diag_info(exanic_t *exanic, int port_number,
                             exanic_sfp_diag_info_t *info)
{
    float rxpwr_4, rxpwr_3, rxpwr_2, rxpwr_1, rxpwr_0, rxpwr_ad;
    uint16_t rxpwr_ad_raw;
    uint16_t txpwr_s_raw, txpwr_ad;
    int16_t txpwr_o;
    float txpwr_s;
    uint16_t t_s_raw;
    float t_s;
    int16_t t_ad, t_o;
    uint8_t diag_type = 0;

    if (port_number < 0 || port_number >= exanic->num_ports)
    {
        exanic_err_printf("invalid port number: %d", port_number);
        return -1;
    }

    /* see Finisar application note AN-2030 */

    /* Check if the SFP has digital diagnostic enabled  */
    if (sfp_read(exanic, port_number, 0xA0, 92, (char *)&diag_type, 1) == -1)
    {
        return -1;
    }
    if ((diag_type & (1 << 6)) == 0)
    {
        return -1;
    }


    /* RX power */
    if (sfp_read_float(exanic, port_number, 0xA2, 56, &rxpwr_4) == -1 ||
            sfp_read_float(exanic, port_number, 0xA2, 60, &rxpwr_3) == -1 ||
            sfp_read_float(exanic, port_number, 0xA2, 64, &rxpwr_2) == -1 ||
            sfp_read_float(exanic, port_number, 0xA2, 68, &rxpwr_1) == -1 ||
            sfp_read_float(exanic, port_number, 0xA2, 72, &rxpwr_0) == -1 ||
            sfp_read_short(exanic, port_number, 0xA2, 104, &rxpwr_ad_raw) == -1)
        return -1;
    rxpwr_ad = rxpwr_ad_raw;

    info->rx_power =
        rxpwr_4 * rxpwr_ad * rxpwr_ad * rxpwr_ad * rxpwr_ad +
        rxpwr_3 * rxpwr_ad * rxpwr_ad * rxpwr_ad +
        rxpwr_2 * rxpwr_ad * rxpwr_ad +
        rxpwr_1 * rxpwr_ad +
        rxpwr_0;

    /* Convert from units of 0.1uW to mW */
    info->rx_power = info->rx_power / 10000;

    /* TX power */
    if (sfp_read_short(exanic, port_number, 0xA2, 80, &txpwr_s_raw) == -1 ||
            sfp_read_short(exanic, port_number, 0xA2, 82,
                (uint16_t *)&txpwr_o) == -1 ||
            sfp_read_short(exanic, port_number, 0xA2, 102, &txpwr_ad) == -1)
        return -1;
    txpwr_s = txpwr_s_raw / 256.0;

    info->tx_power = txpwr_s * txpwr_ad + txpwr_o;

    /* Convert from units of 0.1uW to mW */
    info->tx_power = info->tx_power / 10000;

    /* Temperature */
    if (sfp_read_short(exanic, port_number, 0xA2, 84, &t_s_raw) == -1 ||
            sfp_read_short(exanic, port_number, 0xA2, 86,
                (uint16_t *)&t_o) == -1 ||
            sfp_read_short(exanic, port_number, 0xA2, 96,
                (uint16_t *)&t_ad) == -1)
        return -1;
    t_s = t_s_raw / 256.0;

    info->temp = t_s * t_ad + t_o;

    /* Convert from units of 1/256 deg C to deg C */
    info->temp = info->temp / 256;

    return 0;
}

int exanic_get_qsfp_diag_info(exanic_t *exanic, int port_number,
                             exanic_qsfp_diag_info_t *info)
{
    uint16_t rx_power_raw[4];
    uint16_t tx_bias_raw[4];
    uint16_t temp_raw;
    int i;

    if (port_number < 0 || port_number >= exanic->num_ports)
    {
        exanic_err_printf("invalid port number: %d", port_number);
        return -1;
    }

    if (sfp_read_short(exanic, port_number, 0xA0, 22, &temp_raw) == -1)
        return -1;

    /* Convert from units of 1/256 deg C to deg C */
    info->temp = temp_raw / 256.0;

    for (i = 0; i < 4; i++)
    {
        if (sfp_read_short(exanic, port_number, 0xA0, 34+2*i, &rx_power_raw[i]) ==
                    -1)
            return -1;

        /* Convert from units of 0.1uW to mW */
        info->rx_power[i] = rx_power_raw[i] * 0.0001;

        if (sfp_read_short(exanic, port_number, 0xA0, 42+2*i, &tx_bias_raw[i]) ==
                    -1)
            return -1;

        /* Convert from units of 2uA to mA */
        info->tx_bias[i] = tx_bias_raw[i] * 0.002;
    }

    return 0;
}
