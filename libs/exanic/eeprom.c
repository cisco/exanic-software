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
#include "eeprom.h"

static int get_eeprom_bytes(exanic_eeprom_t *eeprom, size_t offset,
                            size_t len, uint8_t *bytes)
{
    struct
    __attribute__((packed, aligned(__alignof__(struct ethtool_eeprom))))
    {
        struct ethtool_eeprom e;
        char buf[EXANIC_EEPROM_BLOCK_SIZE];
    } stackbuf;

    struct ethtool_eeprom *ee = &stackbuf.e;
    ee->cmd = ETHTOOL_GEEPROM;
    ee->len = len;
    ee->offset = offset;

    eeprom->ifr.ifr_data = (void *)ee;
    int err = ioctl(eeprom->sock, SIOCETHTOOL, &eeprom->ifr);
    if (err)
    {
        exanic_err_printf("GEEPROM: %s", strerror(errno));
        return -1;
    }

    /* fill in magic number. need this token for eeprom write */
    eeprom->magic = ee->magic;
    memcpy(bytes, stackbuf.buf, len);

    return 0;
}

static int set_eeprom_bytes(exanic_eeprom_t *eeprom, size_t offset,
                            size_t len, const uint8_t *bytes)
{
    struct
    __attribute__((packed, aligned(__alignof__(struct ethtool_eeprom))))
    {
        struct ethtool_eeprom e;
        char buf[EXANIC_EEPROM_BLOCK_SIZE];
    } stackbuf;

    struct ethtool_eeprom *ee = &stackbuf.e;
    ee->cmd = ETHTOOL_SEEPROM;
    ee->len = len;
    ee->offset = offset;
    ee->magic = eeprom->magic;
    memcpy(ee->data, bytes, len);

    eeprom->ifr.ifr_data = (void *)ee;
    int err = ioctl(eeprom->sock, SIOCETHTOOL, &eeprom->ifr);
    if (err)
    {
        exanic_err_printf("SEEPROM: %s", strerror(errno));
        return -1;
    }

    return 0;
}

static int get_eeprom_info(exanic_t *exanic, exanic_eeprom_t *eeprom)
{
    memset(eeprom, 0, sizeof *eeprom);

    char ifname[IF_NAMESIZE];
    int err =
        exanic_get_interface_name(exanic, 0, ifname, sizeof ifname);
    if (err)
        return -1;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        exanic_err_printf("failed to create control socket: %s", strerror(errno));
        return -1;
    }

    eeprom->sock = fd;
    strcpy(eeprom->ifr.ifr_name, ifname);

    /* read dummy byte to get the magic number */
    uint8_t dummy;
    err = get_eeprom_bytes(eeprom, 0, 1, &dummy);
    if (err)
        goto err_sock_close;

    return 0;

err_sock_close:
    close(fd);
    return -1;
}

/* allocate an EEPROM handle */
exanic_eeprom_t *exanic_eeprom_acquire(exanic_t *exanic)
{
    exanic_eeprom_t *eeprom = calloc(1, sizeof *eeprom);
    if (!eeprom)
    {
        exanic_err_printf("failed to allocate EEPROM handle");
        return NULL;
    }

    int err = get_eeprom_info(exanic, eeprom);
    if (err)
        goto err_free_eeprom;

    return eeprom;

err_free_eeprom:
    free(eeprom);
    return NULL;
}

/* free an EEPROM handle */
void exanic_eeprom_free(exanic_eeprom_t *eeprom)
{
    close(eeprom->sock);
    free(eeprom);
}

/* write bytes to ExaNIC eeprom */
int exanic_eeprom_write(exanic_eeprom_t *ee, size_t offset,
                        size_t len, const uint8_t *bytes)
{
    if (offset + len > EXANIC_EEPROM_BLOCK_SIZE)
    {
        exanic_err_printf("EEPROM access out of bound");
        return -1;
    }

    return set_eeprom_bytes(ee, offset, len, bytes);
}

/* read bytes from ExaNIC eeprom */
int exanic_eeprom_read(exanic_eeprom_t *ee, size_t offset,
                       size_t len, uint8_t *bytes)
{
    if (offset + len > EXANIC_EEPROM_BLOCK_SIZE)
    {
        exanic_err_printf("EEPROM access out of bound");
        return -1;
    }

    return get_eeprom_bytes(ee, offset, len, bytes);
}
