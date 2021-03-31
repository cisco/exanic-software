/**
 * \file
 * \brief ExaNIC Device Table
 *
 * This file contains device-specific information for ExaNIC products
 */
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

typedef enum
{
    EXANIC_FW_FLASH_CFI,
    EXANIC_FW_FLASH_QSPI
} exanic_fw_flash_type;

struct exanic_fw_flash_info
{
    exanic_fw_flash_type type;
    /* Device, erase and write sizes of the firmware flash
     * only needed if these are not discoverable from the
     * actual hardware (e.g. through CFI) */
    size_t device_size;
    size_t erase_size;
    size_t write_size;
};

/* A list of firmware flash types found among ExaNIC products
 * add more as needed */
static const struct exanic_fw_flash_info exanic_cfi_flash_info =
{
    EXANIC_FW_FLASH_CFI, 0, 0, 0,
};

static const struct exanic_fw_flash_info exanic_x100_flash_info =
{
    EXANIC_FW_FLASH_QSPI,
    /* each flash device has a capacity of 16MB. the X100 firmware unites the
     * two flash devices into a single 32MB address space. flash operations
     * addressed to the lower 16MB are performed on the recovery flash. */
    0x2000000,
    0x1000,
    256,
};

/* A list of hardware feature flags for ExaNIC products */

/* FPGA Development Kit available */
#define EXANIC_HW_FLAG_DEVKIT                    (1ull)
/* Periodic output available */
#define EXANIC_HW_FLAG_PER_OUT                   (1ull << 1)
/* 10Mhz periodic output available */
#define EXANIC_HW_FLAG_PER_OUT_10M               (1ull << 2)
/* Periodic output configs restored from EEPROM */
#define EXANIC_HW_FLAG_PER_OUT_EEP               (1ull << 3)
/* Differential PPS input */
#define EXANIC_HW_FLAG_PPS_DIFF                  (1ull << 4)
/* Single-ended PPS input */
#define EXANIC_HW_FLAG_PPS_SINGLE                (1ull << 5)
/* PPS termination resistor on PCB */
#define EXANIC_HW_FLAG_PPS_TERM                  (1ull << 6)
/* Port mirroring firmware available */
#define EXANIC_HW_FLAG_MIRROR_FW                 (1ull << 7)
/* Variant with on-board DRAM available */
#define EXANIC_HW_FLAG_DRAM_VARIANT              (1ull << 8)
/* Fan speed sensor available */
#define EXANIC_HW_FLAG_FAN_RPM_SENSOR            (1ull << 9)
/* External power supply input sense available */
#define EXANIC_HW_FLAG_PWR_SENSE                 (1ull << 10)
/* PTP grandmaster functionality */
#define EXANIC_HW_FLAG_PTP_GM                    (1ull << 11)
/* GPS input available */
#define EXANIC_HW_FLAG_GPS                       (1ull << 12)

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
    /* Firmware flash info */
    const struct exanic_fw_flash_info *flash_info;
    /* Ethernet port form factor */
    exanic_port_form_factor port_ff;
    /* Device FPGA family */
    exanic_device_family dev_family;
    /* Feature flags */
    uint64_t flags;
};

__attribute__((unused))
static const struct exanic_hw_info exanic_hw_products[] =
{
    {EXANIC_HW_X4, "exanic_x4", 4, 5, 0xA0,
        &exanic_cfi_flash_info, EXANIC_PORT_SFP, EXANIC_XILINX_US,

        EXANIC_HW_FLAG_DEVKIT |
        EXANIC_HW_FLAG_PPS_SINGLE |
        EXANIC_HW_FLAG_PPS_DIFF |
        EXANIC_HW_FLAG_FAN_RPM_SENSOR
    },

    {EXANIC_HW_X2, "exanic_x2", 2, 4, 0xA0,
        &exanic_cfi_flash_info, EXANIC_PORT_SFP, EXANIC_XILINX_US,


        EXANIC_HW_FLAG_DEVKIT |
        EXANIC_HW_FLAG_PPS_SINGLE |
        EXANIC_HW_FLAG_PPS_DIFF |
        EXANIC_HW_FLAG_FAN_RPM_SENSOR
    },

    {EXANIC_HW_X10, "exanic_x10", 2, 4, 0xA0,
        &exanic_cfi_flash_info, EXANIC_PORT_SFP, EXANIC_XILINX_US,

        EXANIC_HW_FLAG_DEVKIT |
        EXANIC_HW_FLAG_PER_OUT |
        EXANIC_HW_FLAG_PPS_SINGLE |
        EXANIC_HW_FLAG_PPS_TERM |
        EXANIC_HW_FLAG_MIRROR_FW
    },

    {EXANIC_HW_X10_GM, "exanic_x10_gm", 2, 4, 0xA0,
        &exanic_cfi_flash_info, EXANIC_PORT_SFP, EXANIC_XILINX_US,

        EXANIC_HW_FLAG_PER_OUT |
        EXANIC_HW_FLAG_PER_OUT_10M |
        EXANIC_HW_FLAG_PER_OUT_EEP |
        EXANIC_HW_FLAG_PPS_SINGLE |
        EXANIC_HW_FLAG_PPS_TERM |
        EXANIC_HW_FLAG_PTP_GM |
        EXANIC_HW_FLAG_GPS
    },

    {EXANIC_HW_X40, "exanic_x40", 2, 4, 0xA0,
        &exanic_cfi_flash_info, EXANIC_PORT_QSFP, EXANIC_XILINX_US,

        EXANIC_HW_FLAG_DEVKIT |
        EXANIC_HW_FLAG_PER_OUT |
        EXANIC_HW_FLAG_PPS_SINGLE |
        EXANIC_HW_FLAG_PPS_TERM
    },

    {EXANIC_HW_X10_HPT, "exanic_x10_hpt", 2, 4, 0xA0,
        &exanic_cfi_flash_info, EXANIC_PORT_SFP, EXANIC_XILINX_US,

        EXANIC_HW_FLAG_PER_OUT |
        EXANIC_HW_FLAG_PER_OUT_10M |
        EXANIC_HW_FLAG_PPS_SINGLE |
        EXANIC_HW_FLAG_PPS_TERM
    },

    {EXANIC_HW_V5P, "exanic_v5p", 2, 4, 0xA0,
        &exanic_cfi_flash_info, EXANIC_PORT_QSFP, EXANIC_XILINX_USP,

        EXANIC_HW_FLAG_DEVKIT |
        EXANIC_HW_FLAG_PER_OUT |
        EXANIC_HW_FLAG_PPS_SINGLE |
        EXANIC_HW_FLAG_PPS_TERM |
        EXANIC_HW_FLAG_FAN_RPM_SENSOR |
        EXANIC_HW_FLAG_PWR_SENSE
    },

    {EXANIC_HW_X25, "exanic_x25", 2, 4, 0xA0,
        &exanic_cfi_flash_info, EXANIC_PORT_SFP, EXANIC_XILINX_USP,

        EXANIC_HW_FLAG_DEVKIT |
        EXANIC_HW_FLAG_PER_OUT |
        EXANIC_HW_FLAG_PPS_SINGLE |
        EXANIC_HW_FLAG_PPS_TERM |
        EXANIC_HW_FLAG_DRAM_VARIANT
    },

    {EXANIC_HW_X100, "exanic_x100", 2, 4, 0xA0,
        &exanic_x100_flash_info, EXANIC_PORT_QSFP, EXANIC_XILINX_USP,

        EXANIC_HW_FLAG_DEVKIT |
        EXANIC_HW_FLAG_PER_OUT |
        EXANIC_HW_FLAG_PPS_SINGLE |
        EXANIC_HW_FLAG_PPS_TERM |
        EXANIC_HW_FLAG_DRAM_VARIANT
    },

    {EXANIC_HW_V9P, "exanic_v9p", 2, 4, 0xA0,
        &exanic_cfi_flash_info, EXANIC_PORT_QSFPDD, EXANIC_XILINX_USP,

        EXANIC_HW_FLAG_DEVKIT |
        EXANIC_HW_FLAG_PER_OUT |
        EXANIC_HW_FLAG_PPS_SINGLE |
        EXANIC_HW_FLAG_PPS_TERM
    },

    {EXANIC_HW_V9P_3, "exanic_v9p3", 2, 4, 0xA0,
        &exanic_cfi_flash_info, EXANIC_PORT_QSFPDD, EXANIC_XILINX_USP,

        EXANIC_HW_FLAG_DEVKIT |
        EXANIC_HW_FLAG_PER_OUT |
        EXANIC_HW_FLAG_PPS_SINGLE |
        EXANIC_HW_FLAG_PPS_TERM
    },
};

#define EXANIC_HW_TABLE_SIZE (sizeof exanic_hw_products/sizeof exanic_hw_products[0])

/* performs look-up in the device table above.
 * sets the hardware ID field to -1 and returns -1 on failure */
static inline int
exanic_get_hw_info(exanic_hardware_id_t hwid, struct exanic_hw_info *info)
{
    unsigned i;
    for (i = 0; i < EXANIC_HW_TABLE_SIZE; i++)
    {
        if (exanic_hw_products[i].hwid == hwid)
        {
            *info = exanic_hw_products[i];
            return 0;
        }
    }

    info->hwid = -1;
    return -1;
}

#endif /* EXANIC_HW_INFO_H */
