/**
 * ExaNIC Link Aggregation driver support for libexanic
 * Copyright (C) 2011-2020 Exablaze Pty Ltd and its licensors
 */
#ifndef _EXANIC_EXABOND_H
#define _EXANIC_EXABOND_H

#include <stdbool.h>
#include <unistd.h>

static inline bool exanic_interface_is_exabond(const char *ifname)
{
    char exabond_devname[IFNAMSIZ * 2];

    /* Easiest way to test is to see if a device matching
     * `ifname` exists among /dev/exabond-*
     *
     * If the exabond driver is managing a bond group, then
     * test whether ifname is an exasock bond interface by
     * checking for the existence of the exabond device file.
     */
    snprintf(exabond_devname, IFNAMSIZ * 2,
             "/dev/exabond-%s", ifname);

    return access(exabond_devname, F_OK | R_OK) == 0;
}

#endif
