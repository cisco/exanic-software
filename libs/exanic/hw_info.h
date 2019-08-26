#ifndef EXANIC_HW_INFO_H
#define EXANIC_HW_INFO_H

#include "pcie_if.h"

typedef enum
{
    EXANIC_PORT_SFP,
    EXANIC_PORT_QSFP,
    EXANIC_PORT_QSFPDD
} exanic_port_form_factor;

typedef enum
{
    /* 7 series */
    EXANIC_XILINX_7,
    /* Ultrascale */
    EXANIC_XILINX_US,
    /* Ultrascale+ */
    EXANIC_XILINX_USP,
} exanic_device_family;

struct exanic_hw_feature
{
    /* Legacy Z-card */
    unsigned zcard              :1;
    /* FPGA Development Kit available */
    unsigned devkit             :1;
    /* Periodic output available */
    unsigned periodic_out       :1;
    /* 10Mhz periodic output available */
    unsigned periodic_out_10m   :1;
    /* Periodic output configs restored from EEPROM */
    unsigned periodic_out_eep   :1;
    /* Differential PPS input */
    unsigned pps_diff           :1;
    /* Single-ended PPS input */
    unsigned pps_single         :1;
    /* PPS termination resistor on PCB */
    unsigned pps_term           :1;
    /* Port mirroring firmware available */
    unsigned mirror_fw          :1;
    /* Variant with on-board DRAM available */
    unsigned dram_variant       :1;
    /* Fan speed sensor available */
    unsigned fan_rpm_sensor     :1;
    /* External power supply input sense available */
    unsigned pwr_sense          :1;
    /* PTP grandmaster functionality */
    unsigned ptp_gm             :1;
    /* GPS input available */
    unsigned gps                :1;
    /* Hardware flow-steering supported */
    unsigned hw_filter          :1;
};

struct exanic_hw_info
{
    /* ExaNIC hardware ID register value */
    int32_t hwid;
    /* Firmware bitstream prefix */
    const char *bitstream_prf;
    /* Number of physical ports */
    unsigned nports;
    /* EEPROM I2C bus number and slave address */
    unsigned eep_bus;
    uint8_t eep_addr;
    /* Ethernet port form factor */
    exanic_port_form_factor port_ff;
    /* Device FPGA family */
    exanic_device_family dev_family;
    /* Feature flags */
    struct exanic_hw_feature flags;
};

__attribute__((unused))
static const struct exanic_hw_info exanic_hw_products[] =
{
    {EXANIC_HW_Z1, NULL, 4, 0, 0, EXANIC_PORT_SFP, EXANIC_XILINX_7,
    {
        .zcard = 1,
        .pps_diff = 1
    }},

    {EXANIC_HW_Z10, NULL, 4, 0, 0, EXANIC_PORT_SFP, EXANIC_XILINX_7,
    {
        .zcard = 1,
        .pps_diff = 1
    }},

    {EXANIC_HW_X4, "exanic_x4", 4, 5, 0xA0, EXANIC_PORT_SFP, EXANIC_XILINX_US,
    {
        .devkit = 1,
        .pps_single = 1,
        .pps_diff = 1,
        .fan_rpm_sensor = 1,
        .hw_filter = 1,
    }},

    {EXANIC_HW_X2, "exanic_x2", 2, 4, 0xA0, EXANIC_PORT_SFP, EXANIC_XILINX_US,
    {
        .devkit = 1,
        .pps_single = 1,
        .pps_diff = 1,
        .fan_rpm_sensor = 1,
        .hw_filter = 1,
    }},

    {EXANIC_HW_X10, "exanic_x10", 2, 4, 0xA0, EXANIC_PORT_SFP, EXANIC_XILINX_US,
    {
        .devkit = 1,
        .periodic_out = 1,
        .pps_single = 1,
        .pps_term = 1,
        .mirror_fw = 1,
        .hw_filter = 1,
    }},

    {EXANIC_HW_X10_GM, "exanic_x10_gm", 2, 4, 0xA0, EXANIC_PORT_SFP, EXANIC_XILINX_US,
    {
        .periodic_out = 1,
        .periodic_out_10m = 1,
        .periodic_out_eep = 1,
        .pps_single = 1,
        .pps_term = 1,
        .ptp_gm = 1,
        .gps = 1,
        .hw_filter = 1,
    }},

    {EXANIC_HW_X40, "exanic_x40", 2, 4, 0xA0, EXANIC_PORT_QSFP, EXANIC_XILINX_US,
    {
        .devkit = 1,
        .periodic_out = 1,
        .pps_single = 1,
        .pps_term = 1,
        .hw_filter = 1,
    }},

    {EXANIC_HW_X10_HPT, "exanic_x10_hpt", 2, 4, 0xA0, EXANIC_PORT_SFP, EXANIC_XILINX_US,
    {
        .periodic_out = 1,
        .periodic_out_10m = 1,
        .pps_single = 1,
        .pps_term = 1,
        .hw_filter = 1,
    }},

    {EXANIC_HW_V5P, "exanic_v5p", 2, 4, 0xA0, EXANIC_PORT_QSFP, EXANIC_XILINX_USP,
    {
        .devkit = 1,
        .periodic_out = 1,
        .pps_single = 1,
        .pps_term = 1,
        .fan_rpm_sensor = 1,
        .pwr_sense = 1,
        .hw_filter = 1,
    }},

    {EXANIC_HW_X25, "exanic_x25", 2, 4, 0xA0, EXANIC_PORT_SFP, EXANIC_XILINX_USP,
    {
        .devkit = 1,
        .periodic_out = 1,
        .pps_single = 1,
        .pps_term = 1,
        .dram_variant = 1,
        .hw_filter = 1,
    }},

    {.hwid = -1}
};

/* performs look-up in the device table above.
 * sets the hardware ID field to -1 and returns -1 on failure */
static inline int
exanic_get_hw_info(exanic_hardware_id_t hwid, struct exanic_hw_info *info)
{
    int i = 0;
    while (1)
    {
        if (exanic_hw_products[i].hwid == -1)
        {
            info->hwid = -1;
            break;
        }

        if (exanic_hw_products[i].hwid == hwid)
        {
            *info = exanic_hw_products[i];
            return 0;
        }

        i++;
    }
    return -1;
}

#endif /* EXANIC_HW_INFO_H */
