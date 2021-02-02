/**
 * \file
 * \brief ExaNIC EEPROM Access
 *
 * This file contains functions and data types for accessing the ExaNIC EEPROM
 */
#ifndef EXANIC_EEPROM_H
#define EXANIC_EEPROM_H

/* fields in the ExaNIC EEPROM */

/* ExaNIC EEPROM block size */
#define EXANIC_EEPROM_BLOCK_SIZE                256

/* port 0 MAC (serial number on Exablaze cards) */
#define EXANIC_EEPROM_MAC_ADDR                  0
#define EXANIC_EEPROM_MAC_ADDR_LEN              6

/* serial number (Cisco cards only) */
#define EXANIC_EEPROM_CISCO_SERIAL              0x10
#define EXANIC_EEPROM_CISCO_SERIAL_LEN          16

/* X10-GM IP address */
#define EXANIC_EEPROM_IP_ADDR                   0x20
#define EXANIC_EEPROM_IP_ADDR_LEN               4

/* X10-GM PTP config word 0 */
#define EXANIC_EEPROM_PTP_CONFIG_0              0x24
#define EXANIC_EEPROM_PTP_CONFIG_0_LEN          4

/* X10-GM PTP config word 1 */
#define EXANIC_EEPROM_PTP_CONFIG_1              0x28
#define EXANIC_EEPROM_PTP_CONFIG_1_LEN          4

/* X10-GM PTP config word 2 */
#define EXANIC_EEPROM_PTP_CONFIG_2              0x2C
#define EXANIC_EEPROM_PTP_CONFIG_2_LEN          4

/* X10-GM leap seconds, little endian */
#define EXANIC_EEPROM_LEAP_SECOND               0x30
#define EXANIC_EEPROM_LEAP_SECONDS_LEN          4

/* bridging and mirroring config */
#define EXANIC_EEPROM_BRIDGE_MIRROR_CONF        0x40
#define EXANIC_EEPROM_BRODGE_MIRROR_CONF_LEN    1

/* special function enable */
#define EXANIC_EEPROM_SPECIAL_FUNC_EN           0x41
#define EXANIC_EEPROM_SPECIAL_FUNC_EN_LEN       1

/* embedded NIC on Fusion x86 module */
#define EXANIC_EEPROM_EMBEDDED_NIC              0x42
#define EXANIC_EEPROM_EMBEDDED_NIC_LEN          1

/* port 0 speed */
#define EXANIC_EEPROM_PORT_SPEED_0              0x50
#define EXANIC_EEPROM_PORT_SPEED_0_LEN          1

/* port 1 speed */
#define EXANIC_EEPROM_PORT_SPEED_1              0x51
#define EXANIC_EEPROM_PORT_SPEED_1_LEN          1

/* port 2 speed */
#define EXANIC_EEPROM_PORT_SPEED_2              0x52
#define EXANIC_EEPROM_PORT_SPEED_2_LEN          1

/* port 3 speed */
#define EXANIC_EEPROM_PORT_SPEED_3              0x53
#define EXANIC_EEPROM_PORT_SPEED_3_LEN          1

/* port 0 config */
#define EXANIC_EEPROM_PORT_CONFIF_0             0x54
#define EXANIC_EEPROM_PORT_CONFIF_0_LEN         1

/* port 1 config */
#define EXANIC_EEPROM_PORT_CONFIF_1             0x55
#define EXANIC_EEPROM_PORT_CONFIF_1_LEN         1

/* port 2 config */
#define EXANIC_EEPROM_PORT_CONFIF_2             0x56
#define EXANIC_EEPROM_PORT_CONFIF_2_LEN         1

/* port 3 config */
#define EXANIC_EEPROM_PORT_CONFIF_3             0x57
#define EXANIC_EEPROM_PORT_CONFIF_3_LEN         1

/* ExaNIC EEPROM handle type */
typedef struct
{
    /* control socket */
    int sock;
    /* magic number passed to driver for EEPROM access */
    uint32_t magic;
    /* used for ioctl requests */
    struct ifreq ifr;
} exanic_eeprom_t;

/* allocate an EEPROM handle */
exanic_eeprom_t *exanic_eeprom_acquire(exanic_t *exanic);

/* free an EEPROM handle */
void exanic_eeprom_free(exanic_eeprom_t *eeprom);

/* write bytes to ExaNIC eeprom */
int exanic_eeprom_write(exanic_eeprom_t *ee, size_t offset,
                        size_t len, const uint8_t *bytes);

/* read bytes from ExaNIC eeprom */
int exanic_eeprom_read(exanic_eeprom_t *ee, size_t offset,
                       size_t len, uint8_t *bytes);

#endif /* EXANIC_EEPROM_H */
