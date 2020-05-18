/**
 * Exasock-bonding driver's obj lib API.
 * Copyright (C) 2011-2020 Exablaze Pty Ltd and its licensors
 */
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include "exasock-bonding-priv.h"
#include "exanic.h"

bool
exasock_bond_slave_id_eq_exanic_ip_dev(const struct exabond_slave_exanic_id *sei,
                                       const struct exanic_ip_dev *eid)
{
    int exa_id, exa_port;

    exasock_exanic_ip_dev_get_id_and_port(eid, &exa_id, &exa_port);
    return sei->exanic_id == exa_id && sei->exanic_port == exa_port;
}

void
exasock_bond_cache_refresh_from_mapping(struct exasock_bond *b)
{
    b->cached_groupinfo.active_slave_id.raw =
        b->mapping->active_slave_id.raw;
}

int
exasock_bond_iface_get_mac_addr(const struct exasock_bond *b,
                                uint8_t *out_mac_addr)
{
    int fd, ifnamelen, err;
    char ifname[IFNAMSIZ * 2];
    struct ifreq ifr;

    err = sscanf(b->devname, "/dev/exabond-%s", ifname);
    if (err != 1)
    {
        perror("Unable to extract iface name for bond dev");
        return -1;
    }

    ifnamelen = strlen(ifname);

    if (ifnamelen >= sizeof(ifr.ifr_name))
        return -1;

    strcpy(ifr.ifr_name, ifname);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        perror("Failed to create socket");
        return -1;
    }

    err = ioctl(fd, SIOCGIFHWADDR, &ifr);
    if (err != 0)
    {
        perror("IOCTL to get mac addr failed.");
        goto out_close_socket;
    }

    close(fd);

    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
        return -1;

    memcpy(out_mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    return 0;

out_close_socket:
    close(fd);
    return -1;
}

int
exasock_bond_init(struct exasock_bond *b, const char *ifname)
{
    char devname[IFNAMSIZ * 2];
    int fd, ret;
    void *mapping;

    snprintf(devname, IFNAMSIZ * 2, "/dev/exabond-%s", ifname);
    fd = open(devname, O_RDONLY);

    if (fd == -1)
    {
        perror(devname);
        return errno;
    }

    mapping = mmap(NULL, EXASOCK_BOND_MAPPING_SIZE, PROT_READ, MAP_PRIVATE,
                   fd, 0);

    if (mapping == MAP_FAILED)
    {
        perror(devname);
        ret = errno;
        goto out_mapfailed;
    }

    b->fd = fd;
    b->mapping = mapping;
    b->dev_handles_lock = 0;
    strncpy(b->devname, devname, IFNAMSIZ * 2);

    /* Initialize the cached groupinfo */
    exasock_bond_cache_refresh_from_mapping(b);
    return 0;

out_mapfailed:
    close(fd);
    return ret;
}

void
exasock_bond_destroy(struct exasock_bond *b)
{
    if (b == NULL)
        return;

    if (b->mapping)
        munmap(b->mapping, EXASOCK_BOND_MAPPING_SIZE);

    close(b->fd);

    b->mapping = NULL;
    b->fd = 0;
    b->dev_handles_lock = 0;
    b->devname[0] = '\0';
}
