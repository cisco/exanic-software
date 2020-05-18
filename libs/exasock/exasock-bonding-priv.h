/**
 * Exasock-bonding driver's object lib API
 * Copyright (C) 2011-2020 Exablaze Pty Ltd and its licensors
 */
#ifndef _EXASOCK_EXABOND_H
#define _EXASOCK_EXABOND_H

#include <assert.h>
#include <sched.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <sys/time.h>

#include "lock.h"
#include "rwlock.h"
#include "structs.h"
#include "kernel/exasock-bonding.h"

#ifndef PAGE_SIZE
#define EXASOCK_BOND_MAPPING_SIZE    (4096)
#else
#define EXASOCK_BOND_MAPPING_SIZE    (PAGE_SIZE)
#endif

struct exasock_bond
{
    int fd;
    char devname[IFNAMSIZ * 2];

    /* SYNCHRONIZATION NOTES:
     * The exasock_poll_lock serializes access to the DMA buffers of all
     * the exanic ports acquired in the exanic_ctx_list, and prevents
     * the race condition where multiple threads read the DMA rings at
     * the same time and then deliver the same incoming frame twice to
     * the same target socket.
     *
     * The `exa_socket::lock` serializes the per-socket packet list.
     *
     * Neither of these two locks is sufficient to ensure that multiple
     * threads will not race each other to modify the metadata jointly
     * maintained inside of exanic_ip::dev and exanic_ip::bond::last_rx_dev.
     * These two variables require their own serialization domain, especially
     * because they are modified *both* on the exanic_poll() path *AND* on
     * the exanic_send() path (because
     * exasock_exanic_ip_propagate_link_state_changes()) is called in both
     * of those paths.
     *
     * Bear in mind: the intention is *not* to serialize accesses to the
     * groupinfo metadata. That metadata is read-only from userspace, and
     * already protected against partial reads by the fact that it's
     * atomically updated in one atomic_set.
     * It is perfectly legal for multiple threads to read the groupinfo.
     *
     * This lock is solely for preventing concurrent writes to the
     * struct exanic_ip_dev instances maintained by a bond
     * (exasock_bond::last_rx_dev and exanic_ip::dev).
     */
    volatile uint32_t dev_handles_lock;
    struct exanic_ip_dev last_rx_dev;
    struct exabond_master_groupinfo *mapping, cached_groupinfo;
};

/** Given a previous groupinfo value as input, will idle-spin poll
 * on the groupinfo until the groupinfo's generation has passed the
 * input generation.
 */
static inline void
exabond_groupinfo_wait_for_update(const struct exabond_master_groupinfo *gi,
                                  const struct exabond_master_groupinfo *prev_gi)
{
    while (!exabond_groupinfo_update_check(gi, prev_gi))
        sched_yield();
}

static inline const char *
exasock_bond_get_devname(const struct exasock_bond *b)
{
    return b->devname;
}

int exasock_bond_iface_get_mac_addr(const struct exasock_bond *b,
                                    uint8_t *out_mac_addr);

int exasock_bond_init(struct exasock_bond *b, const char *ifname);
void exasock_bond_destroy(struct exasock_bond *b);

static inline bool
exasock_bond_update_check(const struct exasock_bond *b)
{
    return exabond_groupinfo_update_check(b->mapping,
                                          &b->cached_groupinfo);
}

bool exasock_exanic_ip_dev_is_initialized(const struct exanic_ip_dev *eid);

static inline struct exanic_ip_dev *
exasock_bond_get_last_rx_dev(struct exasock_bond *b)
{
    if (exasock_exanic_ip_dev_is_initialized(&b->last_rx_dev))
        return &b->last_rx_dev;

    return NULL;
}

void exasock_bond_cache_refresh_from_mapping(struct exasock_bond *b);

bool exasock_bond_slave_id_eq_exanic_ip_dev(const struct exabond_slave_exanic_id *sei,
                                            const struct exanic_ip_dev *eid);

#endif
