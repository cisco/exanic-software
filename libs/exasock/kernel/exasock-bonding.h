/**
 * Exasock-bonding driver's exported metadata API.
 * Copyright (C) 2011-2020 Exablaze Pty Ltd and its licensors
 *
 * This file contains the metadata structs which are exported by the
 * exasock-bonding device files which can be mmap()'d in userspace.
 */

#ifndef _EXABOND_H
#define _EXABOND_H

#define THISMOD_NAME_STRING "exabond"

enum exabond_groupinfo_flags
{
    /* Indicates that this slave is the active one in active-backup mode. */
    EXABOND_GRPINFO_FLAG_ACTIVE = (1 << 0)
};

struct exabond_slave_exanic_id
{
    /* Guide for the perplexed user of this data structure in userspace:
     *
     * If EXABOND_GRPINFO_FLAG_ACTIVE is not set, then exanic_id
     * and exanic_port are in are to be ignored by userspace.
     * If the ACTIVE flag is set, then the exanic_id and exanic_port
     * members are valid and indicate the current active link's ID and
     * port.
     */
    uint16_t flags;
    uint8_t exanic_id, exanic_port;
};

/* This data structure is a per-exabond device structure which is mapped into
 * userspace when mmap() is called on an exabond dev. It indicates the exanic
 * ID and port of the current active link in the bond, if one exists.
 *
 * The data structure is a single atomic integer into which are packed
 * the active exanic ID and port as well as flags to indicate whether the
 * bond is active.
 *
 * We accept that it is possible for the kernel to remove an exanic port from
 * a bond group immediately after userspace reads `active_slave_id`. This will
 * cause userspace to do a stale read/write from/to an exanic that is no longer
 * a member of the group. We accept this.
 *
 * What we theoretically need to worry about is us reading/writing from/to an
 * exanic that has been hotplug-removed, or otherwise removed from existence --
 * but in reality we actually don't need to worry about that because in order
 * for userspace to read/write from/to an exanic, that exanic must be mmap()ed
 * into userspace but Linux's refcount on the mmap()ed the exanic device
 * should act as our guarantor while  we still have that device mmap()ed, that
 * it is safe to read/write from/to that device and that the device has
 * not disappeared.
 */
struct exabond_master_groupinfo
{
    union
    {
        struct exabond_slave_exanic_id typed;
        uint32_t raw;
    } active_slave_id;
};

inline static bool
exabond_groupinfo_active_id_and_port_eq(const struct exabond_master_groupinfo *g,
                                        const int id, const int port)
{
    return (g->active_slave_id.typed.exanic_id == id
            && g->active_slave_id.typed.exanic_port == port);
}

inline static bool
exabond_groupinfo_link_is_active(const struct exabond_master_groupinfo *g)
{
    return !!(g->active_slave_id.typed.flags & EXABOND_GRPINFO_FLAG_ACTIVE);
}

inline static bool
exabond_groupinfo_update_check(const struct exabond_master_groupinfo *g,
                               const struct exabond_master_groupinfo *prev_gi)
{
    return g->active_slave_id.raw != prev_gi->active_slave_id.raw;
}

#endif /* EXABOND_H */
