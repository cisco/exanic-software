/**
 * ExaNIC driver
 * Copyright (C) 2011-2019 Exablaze Pty Ltd and its licensors
 */

#ifndef _EXANIC_I2C_H_
#define _EXANIC_I2C_H_

#include <linux/i2c.h>
#include <linux/i2c-algo-bit.h>

/* EEPROM block size */
#define EXANIC_EEPROM_SIZE              256
/* EEPROM page size */
#define EXANIC_EEPROM_PAGE_SIZE         16

/* Port flags configuration base, 1 byte for each port */
#define EXANIC_EEPROM_PORT_CFG          0x54
#define EXANIC_EEPROM_AUTONEG           0x01

#define SFP_DIAG_ADDR                   0xA2
#define SFP_EEPROM_ADDR                 0xA0

/* External PHY chip bytes */
#define EXANIC_PHY_RESET_OFFSET         0x7f
#define EXANIC_PHY_RXCLK_OFFSET         0x0A

#define EXANIC_PHY_RXGAIN_OFFSET        0x10
#define EXANIC_PHY_RXBOOST_OFFSET       0x11
#define EXANIC_PHY_RXOC_OFFSET          0x12
#define EXANIC_PHY_TXODSW_OFFSET        0x16
#define EXANIC_PHY_TXODPE_OFFSET        0x17
#define EXANIC_PHY_TXODSLEW_OFFSET      0x18

#define EXANIC_PHY_RXGAIN_MASK          0x7f
#define EXANIC_PHY_RXBOOST_MASK         0x1f
#define EXANIC_PHY_RXOC_MASK            0x1f
#define EXANIC_PHY_TXODSW_MASK          0x07
#define EXANIC_PHY_TXODPE_MASK          0x1f
#define EXANIC_PHY_TXODSLEW_MASK        0x07

/* External PHY RXCLK register bits */
#define EXANIC_PHY_RXCLK_BIT_DIAG_LB    6

/* I2C adapter types */
#define EXANIC_I2C_ADAP_SFP             0
#define EXANIC_I2C_ADAP_QSFP            1
#define EXANIC_I2C_ADAP_QSFPDD          2
#define EXANIC_I2C_ADAP_PHY             3
#define EXANIC_I2C_ADAP_EEP             4

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

/* this derived class is used for physical ports of
 * QSFP and QSFP-DD form factor */

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

int exanic_get_serial(struct exanic *exanic, unsigned char serial[ETH_ALEN]);
int exanic_poweron_port(struct exanic *exanic, unsigned port);
int exanic_poweroff_port(struct exanic *exanic, unsigned port);
int exanic_save_feature_cfg(struct exanic *exanic);
int exanic_save_speed(struct exanic *exanic, unsigned port,
                            unsigned speed);
int exanic_save_autoneg(struct exanic *exanic, unsigned port,
                              bool autoneg);
int exanic_set_speed(struct exanic *exanic, unsigned port,
                           unsigned old_speed, unsigned speed);

int exanic_i2c_sfp_get_id(struct exanic *exanic, int port, uint8_t *id);
int exanic_i2c_sfp_has_diag_page(struct exanic *exanic, int port, bool *has_diag);

int exanic_i2c_qsfp_has_upper_pages(struct exanic *exanic, int port, bool *has_pages);
int exanic_i2c_qsfp_page_select(struct exanic *exanic, int port,
                                uint8_t page);

int exanic_i2c_qsfpdd_has_upper_pages(struct exanic *exanic, int port,
                                      bool *has_pages);
int exanic_i2c_qsfpdd_page_select(struct exanic *exanic, int port,
                                  uint8_t bank, uint8_t page);

/* raw r/w functions to pluggable transceivers */
int exanic_i2c_sfp_read(struct exanic *exanic, int port, uint8_t devaddr,
                        uint8_t regaddr, uint8_t *buffer, size_t size);
int exanic_i2c_sfp_write(struct exanic *exanic, int port, uint8_t devaddr,
                         uint8_t regaddr, uint8_t *buffer, size_t size);

/* raw r/w functions to x2 and x4 external phy */
int exanic_i2c_phy_write(struct exanic *exanic, int phy_number,
                         uint8_t regaddr, uint8_t *buffer, size_t size);
int exanic_i2c_phy_read(struct exanic *exanic, int phy_number,
                        uint8_t regaddr, uint8_t *buffer, size_t size);

/* raw r/w functions to the exanic eeprom */
int exanic_i2c_eeprom_read(struct exanic *exanic, uint8_t regaddr,
                           uint8_t *buffer, size_t size);
int exanic_i2c_eeprom_write(struct exanic *exanic, uint8_t regaddr,
                            uint8_t *buffer, size_t size);

#endif /* _EXANIC_I2C_H_ */

