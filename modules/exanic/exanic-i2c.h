/**
 * I2C logic for ExaNIC cards
 * Copyright (C) 2011-2019 Exablaze Pty Ltd and its licensors
 */

#ifndef _EXANIC_I2C_H_
#define _EXANIC_I2C_H_

#include <linux/i2c.h>
#include <linux/i2c-algo-bit.h>

/* EEPROM block size */
#define EXANIC_EEPROM_SIZE                  256
/* EEPROM page size */
#define EXANIC_EEPROM_PAGE_SIZE             16

/* Port flags configuration base, 1 byte for each port */
#define EXANIC_EEPROM_PORT_CFG              0x54
#define EXANIC_EEPROM_AUTONEG               0x01

/* External PHY chip bytes */
#define EXANIC_EXT_PHY_RESET_OFFSET         0x7f
#define EXANIC_EXT_PHY_RXCLK_OFFSET         0x0A

#define EXANIC_EXT_PHY_RXGAIN_OFFSET        0x10
#define EXANIC_EXT_PHY_RXBOOST_OFFSET       0x11
#define EXANIC_EXT_PHY_RXOC_OFFSET          0x12
#define EXANIC_EXT_PHY_TXODSW_OFFSET        0x16
#define EXANIC_EXT_PHY_TXODPE_OFFSET        0x17
#define EXANIC_EXT_PHY_TXODSLEW_OFFSET      0x18

#define EXANIC_EXT_PHY_RXGAIN_MASK          0x7f
#define EXANIC_EXT_PHY_RXBOOST_MASK         0x1f
#define EXANIC_EXT_PHY_RXOC_MASK            0x1f
#define EXANIC_EXT_PHY_TXODSW_MASK          0x07
#define EXANIC_EXT_PHY_TXODPE_MASK          0x1f
#define EXANIC_EXT_PHY_TXODSLEW_MASK        0x07

/* External PHY RXCLK register bits */
#define EXANIC_EXT_PHY_RXCLK_BIT_DIAG_LB    6

/* I2C adapter types */
#define EXANIC_I2C_ADAP_SFP                 0
#define EXANIC_I2C_ADAP_QSFP                1
#define EXANIC_I2C_ADAP_QSFPDD              2
#define EXANIC_I2C_ADAP_EXT_PHY             3
#define EXANIC_I2C_ADAP_EEP                 4

/* I2C slave addresses to access pluggable transceiver memory pages */
#define SFP_DIAG_ADDR                       0xA2
#define XCVR_EEPROM_ADDR                    0xA0

/* Fields in pluggable transceiver memory map */

#define SFF_8024_ID_BYTE                    0

#define SFP_DIAG_MON_BYTE                   92
#define SFP_DIAG_MON_BIT                    6

#define QSFP_FLAT_MEM_BYTE                  2
#define QSFP_FLAT_MEM_BIT                   2
#define QSFP_TX_DISABLE_BYTE                86
#define QSFP_POWER_SET_BYTE                 93
#define QSFP_POWER_OVERRIDE_BIT             0
#define QSFP_POWER_SET_BIT                  1
#define QSFP_PAGE_SEL_BYTE                  127

#define CMIS_FLAT_MEM_BYTE                  2
#define CMIS_FLAT_MEM_BIT                   7

#define CMIS_REV_COMP_BYTE                  1
#define CMIS_BANK_SEL_BYTE                  126
#define CMIS_PAGE_SEL_BYTE                  127

/* Lower page */
#define CMIS_APP_ADV_BYTE                   86

/* Upper page 01h */
#define CMIS_MEDIA_LANE_BYTE                176

/* Upper page 10h */
#define CMIS_DPATH_PWR_CTRL_BYTE            128
#define CMIS_TX_DISABLE_BYTE                130
#define CMIS_CTRL_SET_0_APPLY_INIT_BYTE     143
#define CMIS_CTRL_SET_0_APSEL_BYTE          145
#define CMIS_CTRL_SET_0_TX_CDR_CTRL_BYTE    160
#define CMIS_CTRL_SET_0_RX_CDR_CTRL_BYTE    161

#define CMIS_REV_BYTE(M, m)                 (((M) << 4)|(m))

struct exanic_i2c_data
{
    struct exanic *exanic;
    /* i2c adapter type, see above */
    int type;
    /* physical bus number */
    int bus_number;
    /* i2c adapter and algorithm data */
    struct i2c_adapter adap;
    struct i2c_algo_bit_data bit_data;

    /* write transactions limits:
     * cannot cross page boundary and cannot exceed write_len
     * 0 for either field means "unlimited"
     *
     * XXX: this should really be associated with slave rather than
     *      master. */
    size_t write_len;
    size_t page_len;

    struct list_head link;
    int (*xfer_wrapped)(struct i2c_adapter *,
                        struct i2c_msg *, int);
};

/* this struct is used for physical ports of QSFP and QSFP-DD form factor */

struct exanic_i2c_data_qsfp_common
{
    struct exanic_i2c_data i2c_data;
    /* physical port number */
    int phys_port;
    /* information used during page and bank selection
     * required because it is possible to select the wrong upper page
     * during random read and write sequences unless page selection
     * takes place in the same MODSEL bracket */
    union
    {
        struct
        {
            uint8_t page_switch :1;
            uint8_t qsfp        :1;
            uint8_t cmis_4      :1;
        } fields;
        uint8_t data;
    } flags;
    uint8_t page;
    uint8_t bank;
};

int exanic_i2c_init(struct exanic *exanic);
void exanic_i2c_exit(struct exanic *exanic);

/* EEPROM functions */
int exanic_get_serial(struct exanic *exanic, unsigned char serial[ETH_ALEN]);
int exanic_save_feature_cfg(struct exanic *exanic);
int exanic_save_speed(struct exanic *exanic, unsigned port,
                      unsigned speed);
int exanic_save_autoneg(struct exanic *exanic, unsigned port,
                        bool autoneg);

/* return the SFF-8024 id of the pluggable transceiver */
int exanic_i2c_xcvr_sff8024_id(struct exanic *exanic, int port, uint8_t *id);

/* whether the diagnostics monitoring interface exists */
int exanic_i2c_sfp_has_diag_page(struct exanic *exanic, int port_number, bool *has_diag);

/* check whether the upper page can be switched */
int exanic_i2c_qsfp_flat_mem(struct exanic *exanic, int port, bool *flat);
/* QSFP upper page selection logic */
int exanic_i2c_qsfp_page_sel(struct exanic *exanic, int port, uint8_t page);

/* CMIS revision compliance */
int exanic_i2c_cmis_rev(struct exanic *exanic, int port, uint8_t *rev);
/* check whether the upper page and bank can be switched */
int exanic_i2c_cmis_flat_mem(struct exanic *exanic, int port, bool *flat);
/* CMIS upper page selection logic */
int exanic_i2c_cmis_page_sel(struct exanic *exanic, int port,
                             uint8_t bank, uint8_t page);

/* raw r/w functions to pluggable transceivers */
int exanic_i2c_xcvr_read(struct exanic *exanic, int port, uint8_t devaddr,
                         uint8_t regaddr, uint8_t *buffer, size_t size);
int exanic_i2c_xcvr_write(struct exanic *exanic, int port, uint8_t devaddr,
                          uint8_t regaddr, uint8_t *buffer, size_t size);

/* raw r/w functions to x2 and x4 external phy */
int exanic_i2c_ext_phy_write(struct exanic *exanic, int phy_number,
                             uint8_t regaddr, uint8_t *buffer, size_t size);
int exanic_i2c_ext_phy_read(struct exanic *exanic, int phy_number,
                            uint8_t regaddr, uint8_t *buffer, size_t size);

/* raw r/w functions to the exanic eeprom */
int exanic_i2c_eeprom_read(struct exanic *exanic, uint8_t regaddr,
                           uint8_t *buffer, size_t size);
int exanic_i2c_eeprom_write(struct exanic *exanic, uint8_t regaddr,
                            uint8_t *buffer, size_t size);

#endif /* _EXANIC_I2C_H_ */

