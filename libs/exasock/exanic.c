#include "common.h"

#include <netinet/ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <linux/if_vlan.h>

#if HAVE_NET_TSTAMP_H
#include <linux/net_tstamp.h>
#else
#include "net_tstamp_compat.h"
#endif
#ifndef SIOCGHWTSTAMP
#define SIOCGHWTSTAMP 0x89b1
#endif

#include <exanic/exanic.h>
#include <exanic/fifo_rx.h>
#include <exanic/fifo_tx.h>
#include <exanic/config.h>
#include <exanic/port.h>
#include <exanic/time.h>

#include "kernel/consts.h"
#include "kernel/structs.h"
#include "override.h"
#include "lock.h"
#include "rwlock.h"
#include "structs.h"
#include "exanic.h"
#include "checksum.h"
#include "ether.h"
#include "ip.h"
#include "udp.h"
#include "tcp_buffer.h"
#include "tcp.h"
#include "sys.h"
#include "dst.h"
#include "udp_queue.h"
#include "notify.h"

#define MAX_HDR_LEN 128
#define MAX_FRAME_LEN 1522

struct exanic_ip
{
    struct exa_eth eth;
    struct exa_ip ip;

    exanic_t *exanic;
    exanic_rx_t *exanic_rx;
    exanic_tx_t *exanic_tx;

    char ifname[IFNAMSIZ];
    char device[16];
    int port_number;

    uint8_t eth_dev_addr[ETH_ALEN];
    uint16_t vlan_id;
    exanic_if_addr_t ifaddr;

    bool rx_hw_timestamp;

    /* Need exanic_ip_ctx_lock to modify refcount and add to linked list.
     * Additionally need exasock_poll_lock to remove from linked list - this
     * guarantees that iterating over the list is safe while exasock_poll_lock
     * is held. */
    int refcount;
    struct exanic_ip *next;
};

static struct exanic_ip *exanic_ctx_list;
static int exanic_ctx_all_refcount;
static bool exanic_ctx_need_cleanup;

/* This lock protects modifications to the exanic_ip linked list */
static uint32_t exanic_ip_ctx_lock __attribute__((aligned (64)));

/* Tx lock protects the hardware tx buffer and associated structs */
static uint32_t exanic_tx_lock __attribute__((aligned (64)));

struct exanic_udp
{
    struct exa_eth_tx eth;
    struct exa_ip_tx ip;
    struct exa_udp_tx udp;
    struct exa_dst dst;

    struct exanic_ip *exanic_ctx;
};

struct exanic_tcp
{
    struct exa_eth_tx eth;
    struct exa_ip_tx ip;
    struct exa_tcp_conn tcp;
    struct exa_dst dst;

    struct exanic_ip *exanic_ctx;
    struct exanic_tcp *next;
};

static inline void
exa_get_system_time(struct exa_timestamp * restrict ts)
{
    struct timespec tv;

    if (clock_gettime(CLOCK_REALTIME, &tv) == 0)
    {
        ts->sec = tv.tv_sec;
        ts->nsec = tv.tv_nsec;
    }
    else
        ts->sec = ts->nsec = 0;
}

static inline void
exanic_get_hardware_time(exanic_t *exanic, exanic_cycles32_t cycles32,
                         struct exa_timestamp * restrict ts)
{
    const exanic_cycles_t cycles = exanic_expand_timestamp(exanic, cycles32);
    struct timespec tspec;
    exanic_cycles_to_timespec(exanic, cycles, &tspec);

    ts->sec = tspec.tv_sec;
    ts->nsec = tspec.tv_nsec;
}

/* Send a packet on a ExaNIC */
static inline void
exanic_send(struct exanic_ip * restrict ctx, char *hdr, size_t hdr_len,
            const struct iovec * restrict iov, size_t iovcnt, size_t skip_len,
            size_t data_len)
{
    char *tx_buf, *p;
    size_t offs;
    size_t i;
    size_t frame_len = hdr_len + data_len;
    size_t iov_len = skip_len + data_len;
    int trial;

    assert(hdr_len <= MAX_HDR_LEN);
    assert(ctx->refcount > 0);

    if (frame_len > MAX_FRAME_LEN)
        return;

    exa_lock(&exanic_tx_lock);

    for (trial = 0; trial < 65536; trial++)
    {
        tx_buf = exanic_begin_transmit_frame(ctx->exanic_tx, frame_len);
        if(tx_buf != NULL)
            break;
    }

    if (tx_buf == NULL)
    {
        /* timed out waiting for tx buffer, fail silently for now... */
        exa_unlock(&exanic_tx_lock);
        return;
    }

    memcpy(tx_buf, hdr, hdr_len);

    offs = 0;
    p = tx_buf + hdr_len;
    for (i = 0; i < iovcnt && offs < iov_len; i++)
    {
        size_t len = iov[i].iov_len < iov_len - offs
                   ? iov[i].iov_len : iov_len - offs;
        size_t skip = offs < skip_len ? skip_len - offs : 0;
        if (skip < len)
        {
            memcpy(p, iov[i].iov_base + skip, len - skip);
            p += len - skip;
        }
        offs += len;
    }
    assert(offs == iov_len);

    exanic_end_transmit_frame(ctx->exanic_tx, 0);

    exa_unlock(&exanic_tx_lock);
}

static void
__exanic_ip_update_timestamping(struct exanic_ip * restrict ctx)
{
    struct hwtstamp_config hwtc;
    struct ifreq ifr;
    int fd;

    assert(exasock_override_is_off());

    memset(&hwtc, 0, sizeof(hwtc));
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ctx->ifname);
    ifr.ifr_data = (void *)&hwtc;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (ioctl(fd, SIOCGHWTSTAMP, &ifr) == 0)
        ctx->rx_hw_timestamp = (hwtc.rx_filter != HWTSTAMP_FILTER_NONE);

    close(fd);
}

void
exanic_ip_update_timestamping(const char *ifname)
{
    struct exanic_ip *ctx;

    exa_lock(&exanic_ip_ctx_lock);
    exasock_override_off();

    for (ctx = exanic_ctx_list; ctx != NULL; ctx = ctx->next)
        if (strcmp(ctx->ifname, ifname) == 0)
            __exanic_ip_update_timestamping(ctx);

    exasock_override_on();
    exa_unlock(&exanic_ip_ctx_lock);
}

/* Allocate new exanic_ip context */
static struct exanic_ip *
exanic_ip_alloc(const char *ifname, const char *device,
                int port_number, uint16_t vlan_id,
                in_addr_t address, in_addr_t netmask, in_addr_t broadcast)
{
    struct exanic_ip *ctx;
    exanic_t *exanic;
    exanic_rx_t *exanic_rx;
    exanic_tx_t *exanic_tx;

    assert(exanic_ip_ctx_lock);
    assert(exasock_override_is_off());

    exanic = exanic_acquire_handle(device);
    if (exanic == NULL)
        goto err_acquire_handle;

    exanic_rx = exanic_acquire_rx_buffer(exanic, port_number, 0);
    if (exanic_rx == NULL)
        goto err_acquire_rx_buffer;

    exanic_tx = exanic_acquire_tx_buffer(exanic, port_number, 0);
    if (exanic_tx == NULL)
        goto err_acquire_tx_buffer;

    /* Create the exanic_ip struct */
    ctx = malloc(sizeof(struct exanic_ip));
    if (ctx == NULL)
        goto err_malloc;

    memset(ctx, 0, sizeof(*ctx));
    ctx->exanic = exanic;
    ctx->exanic_rx = exanic_rx;
    ctx->exanic_tx = exanic_tx;
    strncpy(ctx->ifname, ifname, sizeof(ctx->ifname) - 1);
    strncpy(ctx->device, device, sizeof(ctx->device) - 1);
    ctx->port_number = port_number;
    ctx->refcount = 0;
    ctx->next = NULL;

    /* Get interface options */
    __exanic_ip_update_timestamping(ctx);

    /* Initialise the stack */
    exanic_get_mac_addr(exanic, port_number, ctx->eth_dev_addr);
    ctx->vlan_id = vlan_id;
    exa_eth_init(&ctx->eth, ctx->eth_dev_addr, vlan_id);

    ctx->ifaddr.address = address;
    ctx->ifaddr.broadcast = broadcast;
    ctx->ifaddr.netmask = netmask;
    exa_ip_init(&ctx->ip, address, broadcast, netmask);

    return ctx;

err_malloc:
    exanic_release_tx_buffer(exanic_tx);
err_acquire_tx_buffer:
    exanic_release_rx_buffer(exanic_rx);
err_acquire_rx_buffer:
    exanic_release_handle(exanic);
err_acquire_handle:
    return NULL;
}

static void
exanic_ip_free(struct exanic_ip *ctx)
{
    exanic_release_rx_buffer(ctx->exanic_rx);
    exanic_release_handle(ctx->exanic);

    exa_ip_cleanup(&ctx->ip);
    exa_eth_cleanup(&ctx->eth);

    free(ctx);
}

static void
exanic_ip_get_real_device(const char *ifname_in, char *ifname_out,
                          size_t ifname_out_len, uint16_t *vlan_id)
{
    struct vlan_ioctl_args args;
    int fd;

    assert(exasock_override_is_off());

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&args, 0, sizeof(args));
    strncpy(args.device1, ifname_in, sizeof(args.device1) - 1);

    args.cmd = GET_VLAN_REALDEV_NAME_CMD;
    if (ioctl(fd, SIOCGIFVLAN, &args) == -1)
    {
        strncpy(ifname_out, ifname_in, ifname_out_len-1);
        ifname_out[ifname_out_len-1] = 0;
        *vlan_id = 0;
        close(fd);
        return;
    }

    strncpy(ifname_out, args.u.device2, ifname_out_len-1);
    ifname_out[ifname_out_len-1] = 0;

    args.cmd = GET_VLAN_VID_CMD;
    ioctl(fd, SIOCGIFVLAN, &args); /* ignore failure, VID should be 0 */
    *vlan_id = htons(args.u.VID); /* kept in network byte order */
    close(fd);
}

static bool
exanic_ip_lookup(in_addr_t address,
                 char *ifname, size_t ifname_len,
                 char *device, size_t device_len,
                 int *port_number, uint16_t *vlan_id,
                 in_addr_t *netmask, in_addr_t *broadcast)
{
    struct ifaddrs *ifaddrs;
    struct ifaddrs *ifa;

    assert(exasock_override_is_off());

    if (getifaddrs(&ifaddrs) == -1)
        return false;

    for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;

        if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr != address)
            continue;

        if (!(ifa->ifa_flags & IFF_UP))
            continue;

        exanic_ip_get_real_device(ifa->ifa_name, ifname, ifname_len, vlan_id);
        if (exanic_find_port_by_interface_name(ifname, device, device_len,
                port_number) == -1)
            break; /* exists but not an ExaNIC */

        if ((ifa->ifa_netmask == NULL) || (ifa->ifa_ifu.ifu_broadaddr == NULL))
            break;

        *netmask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
        *broadcast = ((struct sockaddr_in *)ifa->ifa_ifu.ifu_broadaddr)->sin_addr.s_addr;
        freeifaddrs(ifaddrs);
        return true;
    }

    freeifaddrs(ifaddrs);
    return false;
}

/* Return true if the address is an ExaNIC */
bool
exanic_ip_find(in_addr_t address)
{
    char ifname[IFNAMSIZ];
    char device[16];
    int port_number;
    uint16_t vlan_id;
    in_addr_t netmask, broadcast;
    bool ret;

    exasock_override_off();
    ret = exanic_ip_lookup(address, ifname, sizeof(ifname),
                           device, sizeof(device),
                           &port_number, &vlan_id, &netmask, &broadcast);
    exasock_override_on();

    return ret;
}

bool
exanic_ip_find_by_interface(const char *ifname, in_addr_t *addr)
{
    struct ifaddrs *ifaddrs;
    struct ifaddrs *ifa;
    char ifname_real[IFNAMSIZ];
    char device[16];
    int port_number;
    uint16_t vlan_id;

    exasock_override_off();

    if (getifaddrs(&ifaddrs) == -1)
    {
        exasock_override_on();
        return false;
    }

    for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (strcmp(ifa->ifa_name, ifname) != 0)
            continue;

        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;

        if (!(ifa->ifa_flags & IFF_UP))
            continue;

        exanic_ip_get_real_device(ifname, ifname_real, sizeof(ifname_real), &vlan_id);
        if (exanic_find_port_by_interface_name(ifname_real, device, sizeof(device),
                &port_number) == -1)
            break; /* exists but not an ExaNIC */

        *addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
        freeifaddrs(ifaddrs);
        exasock_override_on();
        return true;
    }

    freeifaddrs(ifaddrs);
    exasock_override_on();
    return false;
}

struct exanic_ip *
exanic_ip_acquire(in_addr_t address)
{
    char ifname[IFNAMSIZ];
    char device[16];
    int port_number;
    uint16_t vlan_id;
    in_addr_t netmask, broadcast;
    struct exanic_ip *ctx;

    exa_lock(&exanic_ip_ctx_lock);

    /* Look for existing exanic_ip context */
    for (ctx = exanic_ctx_list; ctx != NULL; ctx = ctx->next)
        if (ctx->ifaddr.address == address)
        {
            ctx->refcount++;
            exa_unlock(&exanic_ip_ctx_lock);
            return ctx;
        }

    /* Allocate new exanic_ip context */
    exasock_override_off();
    if (!exanic_ip_lookup(address, ifname, sizeof(ifname),
                          device, sizeof(device), &port_number,
                          &vlan_id, &netmask, &broadcast))
    {
        exasock_override_on();
        exa_unlock(&exanic_ip_ctx_lock);
        return NULL;
    }
    ctx = exanic_ip_alloc(ifname, device, port_number, vlan_id, address,
                          netmask, broadcast);
    exasock_override_on();

    /* FIXME: Return a more informative error instead of failing silently */
    if (ctx == NULL)
    {
        exa_unlock(&exanic_ip_ctx_lock);
        return NULL;
    }

    /* Add to list of exanic_ip contexts */
    ctx->refcount++;
    ctx->next = exanic_ctx_list;
    exanic_ctx_list = ctx;

    exa_unlock(&exanic_ip_ctx_lock);
    return ctx;
}

void
exanic_ip_acquire_ref(struct exanic_ip *ctx)
{
    exa_lock(&exanic_ip_ctx_lock);
    ctx->refcount++;
    exa_unlock(&exanic_ip_ctx_lock);
}

void
exanic_ip_release(struct exanic_ip *ctx)
{
    exa_lock(&exanic_ip_ctx_lock);
    ctx->refcount--;
    if (ctx->refcount == 0)
        exanic_ctx_need_cleanup = true;
    exa_unlock(&exanic_ip_ctx_lock);
}

static void
exanic_ip_cleanup(void)
{
    struct exanic_ip *ctx, *i;

    exa_lock(&exanic_ip_ctx_lock);

    if (exanic_ctx_all_refcount > 0)
    {
        exa_unlock(&exanic_ip_ctx_lock);
        return;
    }

    /* Grab exasock_poll_lock to make sure exanic_poll() is not currently
     * iterating over the list */
    if (!exa_trylock(&exasock_poll_lock))
    {
        exa_unlock(&exanic_ip_ctx_lock);
        return;
    }

    /* Iterate through list and remove exanic_ip contexts with refcount 0 */
    while (exanic_ctx_list != NULL && exanic_ctx_list->refcount == 0)
    {
        ctx = exanic_ctx_list;
        exanic_ctx_list = ctx->next;
        exanic_ip_free(ctx);
    }

    if (exanic_ctx_list != NULL)
    {
        for (i = exanic_ctx_list; i->next != NULL; i = i->next)
        {
            if (i->next->refcount == 0)
            {
                ctx = i->next;
                i->next = ctx->next;
                exanic_ip_free(ctx);
            }
        }
    }

    exanic_ctx_need_cleanup = false;

    exa_unlock(&exasock_poll_lock);
    exa_unlock(&exanic_ip_ctx_lock);
    return;
}

void
exanic_ip_acquire_all(void)
{
    struct ifaddrs *ifaddrs;
    struct ifaddrs *ifa;
    char ifname[IFNAMSIZ];
    char device[16];
    int port_number;
    in_addr_t address, netmask, broadcast;
    uint16_t vlan_id;
    struct exanic_ip *ctx;

    exa_lock(&exanic_ip_ctx_lock);

    if (exanic_ctx_all_refcount == 0)
    {
        exasock_override_off();

        /* Allocate exanic_ip contexts for all ports */
        if (getifaddrs(&ifaddrs) != -1)
        {
            for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next)
            {
                if (ifa->ifa_addr == NULL)
                    continue;

                if (ifa->ifa_addr->sa_family != AF_INET)
                    continue;

                /* Search for existing exanic_ip context */
                address = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
                for (ctx = exanic_ctx_list; ctx != NULL; ctx = ctx->next)
                    if (ctx->ifaddr.address == address)
                        break;
                if (ctx != NULL)
                    continue;

                /* Check if this is an ExaNIC */
                exanic_ip_get_real_device(ifa->ifa_name, ifname, sizeof(ifname), &vlan_id);
                if (exanic_find_port_by_interface_name(ifname, device, sizeof(device),
                        &port_number) == -1)
                    continue; /* not an ExaNIC */

                if ((ifa->ifa_netmask == NULL) || (ifa->ifa_ifu.ifu_broadaddr == NULL))
                    continue;

                /* Need to create a exanic_ip context for this port */
                netmask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
                broadcast = ((struct sockaddr_in *)ifa->ifa_ifu.ifu_broadaddr)->sin_addr.s_addr;
                ctx = exanic_ip_alloc(ifname, device, port_number, vlan_id,
                                      address, netmask, broadcast);
                if (ctx == NULL)
                    continue;
                ctx->next = exanic_ctx_list;
                exanic_ctx_list = ctx;
            }
            freeifaddrs(ifaddrs);
        }

        exasock_override_on();
    }

    exanic_ctx_all_refcount++;

    exa_unlock(&exanic_ip_ctx_lock);
}

void
exanic_ip_release_all(void)
{
    exa_lock(&exanic_ip_ctx_lock);
    exanic_ctx_all_refcount--;
    if (exanic_ctx_all_refcount == 0)
        exanic_ctx_need_cleanup = true;
    exa_unlock(&exanic_ip_ctx_lock);
}

/* Add IP headers and send packet with data */
static inline void
exanic_ip_send_iov(struct exa_ip_tx * restrict ip,
                   struct exa_eth_tx * restrict eth,
                   struct exa_dst * restrict dst,
                   struct exanic_ip * restrict exanic_ctx,
                   char ** restrict hdr_ptr, size_t * restrict hdr_len,
                   const struct iovec *iov, size_t iovcnt, size_t skip_len,
                   size_t data_len)
{
    exa_ip_build_hdr(ip, hdr_ptr, hdr_len, iov, iovcnt, skip_len, data_len);

    if (exa_dst_update(dst))
        exa_eth_set_dest(eth, dst->eth_addr);

    if (exa_dst_found(dst))
    {
        /* Send directly */
        exa_eth_build_hdr(eth, hdr_ptr, hdr_len, iov, iovcnt, skip_len,
                          data_len);
        exanic_send(exanic_ctx, *hdr_ptr, *hdr_len, iov, iovcnt, skip_len,
                    data_len);
    }
    else
    {
        /* Queue the packet to be sent when neighbour lookup is done */
        exa_sys_dst_queue(dst->ip_addr, *hdr_ptr, *hdr_len, iov, iovcnt,
                          skip_len, data_len);
    }
}

/* Get hardware and software timestamps */
static inline void
exanic_poll_get_timestamp(struct exa_socket * restrict sock,
                          struct exanic_ip * restrict ctx,
                          uint32_t chunk_id, struct exa_timestamp ts[2])
{
    exanic_cycles32_t hwts;

    memset(ts, 0, sizeof(struct exa_timestamp) * 2);

    if (sock->rx_sw_timestamp)
        exa_get_system_time(&ts[0]);

    if (ctx->rx_hw_timestamp)
    {
        hwts = exanic_receive_chunk_timestamp(ctx->exanic_rx, chunk_id);
        exanic_get_hardware_time(ctx->exanic, hwts, &ts[1]);
    }
}

/* Copy packet data to a receive buffer and calculate checksum
 * Part of packet data comes from initial chunk provided via pointer,
 * the rest comes from calls to exanic_receive_chunk_inplace() */
static inline int
exanic_poll_recv_body(exanic_rx_t *rx, size_t skip_len,
                      char *buf1, size_t buf1_len,
                      char *buf2, size_t buf2_len,
                      char *init, size_t init_len,
                      uint64_t * restrict csum, int * restrict more_chunks)
{
    size_t remaining = skip_len + buf1_len + buf2_len;
    size_t offs, part_len;
    ssize_t len;
    char *ptr = NULL, *part;

    assert(exasock_poll_lock);

    *csum = csum_part(init, init_len < remaining ? init_len : remaining, *csum);

    /* Skip */
    if (init_len >= skip_len)
    {
        part = init + skip_len;
        part_len = init_len - skip_len;
    }
    else
    {
        remaining = skip_len + buf1_len + buf2_len - init_len;
        offs = init_len;

        while (true)
        {
            len = exanic_receive_chunk_inplace(rx, &ptr, NULL, more_chunks);
            if (len < 0)
                return -1;

            /* Update checksum */
            *csum = csum_part(ptr, len < remaining ? len : remaining, *csum);

            if (offs + len >= skip_len)
            {
                /* Skip partial chunk */
                part = ptr + (skip_len - offs);
                part_len = len - (skip_len - offs);
                break;
            }

            /* Skip chunk */
            offs += len;
            remaining -= len;

            if (!*more_chunks)
                return -1;
        }
    }

    /* First buffer */
    if (part_len >= buf1_len)
    {
        memcpy(buf1, part, buf1_len);
        part += buf1_len;
        part_len -= buf1_len;
    }
    else
    {
        /* Copy leftover partial chunk to buffer */
        memcpy(buf1, part, part_len);
        remaining = buf1_len + buf2_len - part_len;
        offs = part_len;

        while (true)
        {
            len = exanic_receive_chunk_inplace(rx, &ptr, NULL, more_chunks);
            if (len < 0)
                return -1;

            /* Update checksum */
            *csum = csum_part(ptr, len < remaining ? len : remaining, *csum);

            if (offs + len >= buf1_len)
            {
                /* Copy partial chunk to buffer */
                memcpy(buf1 + offs, ptr, buf1_len - offs);
                part = ptr + (buf1_len - offs);
                part_len = len - (buf1_len - offs);
                break;
            }

            /* Copy chunk to buffer */
            memcpy(buf1 + offs, ptr, len);
            offs += len;
            remaining -= len;

            if (!*more_chunks)
                return -1;
        }
    }

    /* Second buffer */
    if (part_len >= buf2_len)
    {
        memcpy(buf2, part, buf2_len);
        return 0;
    }
    else
    {
        /* Copy leftover partial chunk to buffer */
        memcpy(buf2, part, part_len);
        remaining = buf2_len - part_len;
        offs = part_len;

        while (true)
        {
            len = exanic_receive_chunk_inplace(rx, &ptr, NULL, more_chunks);
            if (len < 0)
                return -1;

            /* Update checksum */
            *csum = csum_part(ptr, len < remaining ? len : remaining, *csum);

            if (offs + len >= buf2_len)
            {
                /* Copy partial chunk to buffer */
                memcpy(buf2 + offs, ptr, buf2_len - offs);
                return 0;
            }

            /* Copy chunk to buffer */
            memcpy(buf2 + offs, ptr, len);
            offs += len;
            remaining -= len;

            if (!*more_chunks)
                return -1;
        }
    }
}

/* Check ExaNIC receive buffers for packets
 * exasock_poll_lock must be held */
int
exanic_poll(void)
{
    char *chunk_end, *eth_hdr, *ip_hdr, *t_hdr, *hdr_end, *data;
    char *buf1, *buf2;
    uint8_t *tcpopt;
    size_t t_len, data_len, skip_len, tcpopt_len;
    size_t buf1_len, buf2_len;
    uint32_t data_seq, ack_seq;
    uint8_t tcp_flags;
    uint16_t tcp_win;
    struct exanic_ip *ctx;
    int eth_proto, ip_proto;
    struct exa_endpoint ep;
    struct exa_timestamp ts[2];
    int more_chunks;
    uint32_t hdr_chunk_id;
    int fd;
    struct exa_socket *sock;
    ssize_t ret;
    uint64_t csum;

    assert(exasock_poll_lock);

    /* Poll all interfaces */
    for (ctx = exanic_ctx_list; ctx != NULL; ctx = ctx->next)
    {
        /* Try to read headers */
        more_chunks = 0;
        ret = exanic_receive_chunk_inplace(ctx->exanic_rx, &eth_hdr,
                                           &hdr_chunk_id, &more_chunks);
        if (ret <= 0)
            continue;
        chunk_end = eth_hdr + ret;

        /* Process headers */
        eth_proto = exa_eth_parse_hdr(&ctx->eth, eth_hdr, chunk_end, &ip_hdr);
        if (eth_proto == htons(ETH_P_IP))
        {
            ip_proto = exa_ip_parse_hdr(&ctx->ip, &ep.addr, ip_hdr, chunk_end,
                                        &t_hdr, &t_len);
            if (ip_proto == IPPROTO_UDP)
            {
                /* Process UDP header */
                if (exa_udp_parse_hdr(t_hdr, chunk_end, t_len,
                                      ipaddr_csum(&ep.addr), &ep.port,
                                      &hdr_end, &data_len, &csum) == -1)
                    goto abort_frame;

                /* Find socket matching this packet */
                if ((fd = exa_udp_lookup(&ep)) == -1)
                    goto abort_frame;
                sock = exa_socket_get(fd);
                exa_lock(&sock->state->rx_lock);

                /* Timestamp processing */
                if (sock->report_timestamp)
                    exanic_poll_get_timestamp(sock, ctx, hdr_chunk_id, ts);

                /* Allocate space in receive queue */
                data = exa_udp_queue_write_alloc(sock, &ep, data_len);
                if (data == NULL)
                    goto abort_udp_rx;

                /* Finish receiving chunks */
                if (exanic_poll_recv_body(ctx->exanic_rx, 0,
                                          data, data_len, NULL, 0,
                                          hdr_end, chunk_end - hdr_end,
                                          &csum, &more_chunks) == -1)
                    goto abort_udp_queue_write;

                /* Finish packet processing */
                if (exa_udp_validate_csum(t_hdr, hdr_end, &csum) == -1)
                    goto abort_udp_queue_write;

                /* Discard packet if it might have been overwritten */
                if (!exanic_receive_chunk_recheck(ctx->exanic_rx, hdr_chunk_id))
                    goto abort_udp_queue_write;

                /* Commit packet to receive queue */
                if (sock->report_timestamp)
                    exa_udp_queue_write_commit(sock, data_len, ts);
                else
                    exa_udp_queue_write_commit(sock, data_len, NULL);

                /* Process socket ready state */
                exa_notify_udp_read_update(sock);

                exa_unlock(&sock->state->rx_lock);

                if (more_chunks)
                    exanic_receive_abort(ctx->exanic_rx);

                return fd;

            abort_udp_queue_write:
                exa_udp_queue_write_abort(sock);
            abort_udp_rx:
                exa_notify_udp_read_update(sock);
                exa_unlock(&sock->state->rx_lock);
                goto abort_frame;
            }
            else if (ip_proto == IPPROTO_TCP)
            {
                /* Process TCP header */
                if (exa_tcp_parse_hdr(t_hdr, chunk_end, t_len,
                                      ipaddr_csum(&ep.addr), &ep.port,
                                      &tcpopt, &tcpopt_len, &hdr_end,
                                      &data_seq, &data_len, &ack_seq,
                                      &tcp_flags, &tcp_win, &csum) == -1)
                    goto abort_frame;

                /* Find socket matching this packet */
                if ((fd = exa_tcp_lookup(&ep)) == -1)
                    goto abort_frame;
                sock = exa_socket_get(fd);
                exa_lock(&sock->state->rx_lock);

                /* Listening sockets are processed in the kernel module */
                if (exa_tcp_listening(&sock->ctx.tcp->tcp))
                    goto abort_tcp_rx;

                /* Packet pre-processing */
                if (exa_tcp_pre_update_state(&sock->ctx.tcp->tcp, tcp_flags,
                                             data_seq, ack_seq, data_len,
                                             tcpopt, tcpopt_len) == -1)
                    goto abort_tcp_rx;

                /* Get a pointer to receive buffer */
                if (exa_tcp_rx_buffer_alloc(sock, tcp_flags, data_seq, data_len,
                                            &skip_len, &buf1, &buf1_len,
                                            &buf2, &buf2_len) == -1)
                {
                    /* Sequence number is out of range
                     * Skip over entire packet and continue packet processing */
                    skip_len = data_len;
                    buf1 = buf2 = NULL;
                    buf1_len = buf2_len = 0;
                }

                /* Finish receiving chunks into receive buffer */
                if (exanic_poll_recv_body(ctx->exanic_rx, skip_len,
                                          buf1, buf1_len, buf2, buf2_len,
                                          hdr_end, chunk_end - hdr_end,
                                          &csum, &more_chunks) == -1)
                    goto abort_tcp_rx_buffer_write;

                /* Finish packet processing */
                if (exa_tcp_validate_csum(t_hdr, hdr_end, &csum) == -1)
                    goto abort_tcp_rx_buffer_write;

                /* Discard packet if it might have been overwritten */
                if (!exanic_receive_chunk_recheck(ctx->exanic_rx, hdr_chunk_id))
                    goto abort_tcp_rx_buffer_write;

                /* Packet is confirmed valid, we can update TCP state
                 * and finalise received data in receive buffer */
                exa_tcp_rx_buffer_commit(sock, data_seq + skip_len,
                                         buf1_len + buf2_len);
                exa_tcp_update_state(&sock->ctx.tcp->tcp, tcp_flags,
                                     data_seq, ack_seq, tcp_win, data_len);

                /* Update socket ready state */
                exa_notify_tcp_update(sock);

                exa_unlock(&sock->state->rx_lock);

                if (more_chunks)
                    exanic_receive_abort(ctx->exanic_rx);

                return fd;

            abort_tcp_rx_buffer_write:
                /* Invalidate received data */
                exa_tcp_rx_buffer_abort(sock, data_seq + skip_len,
                                        buf1_len + buf2_len);
            abort_tcp_rx:
                exa_notify_tcp_update(sock);
                exa_unlock(&sock->state->rx_lock);
                goto abort_frame;
            }
        }

    abort_frame:
        if (more_chunks)
            exanic_receive_abort(ctx->exanic_rx);
    }

    if (exanic_ctx_need_cleanup)
        exanic_ip_cleanup();

    return -1;
}

/* Allocate a stack for sending UDP packets on an ExaNIC */
int
exanic_udp_alloc(struct exa_socket * restrict sock)
{
    struct exanic_udp * restrict ctx;

    assert(sock->state->tx_lock);
    assert(sock->ctx.udp == NULL);

    /* Allocate new exanic_udp context */
    ctx = malloc(sizeof(struct exanic_udp));
    if (ctx == NULL)
        return -1;

    ctx->exanic_ctx = NULL;

    exa_eth_tx_init(&ctx->eth, ETH_P_IP);
    exa_ip_tx_init(&ctx->ip, IPPROTO_UDP);
    exa_udp_tx_init(&ctx->udp);
    exa_dst_init(&ctx->dst);

    sock->ctx.udp = ctx;

    return 0;
}

void
exanic_udp_free(struct exa_socket * restrict sock)
{
    struct exanic_udp * restrict ctx = sock->ctx.udp;

    assert(exa_write_locked(&sock->lock));
    assert(ctx != NULL);

    exa_eth_tx_cleanup(&ctx->eth);
    exa_ip_tx_cleanup(&ctx->ip);
    exa_udp_tx_cleanup(&ctx->udp);
    exa_dst_cleanup(&ctx->dst);
    if (ctx->exanic_ctx)
        exanic_ip_release(ctx->exanic_ctx);
    free(ctx);

    sock->ctx.udp = NULL;
}

void
exanic_udp_get_src(struct exa_socket * restrict sock, in_addr_t *addr,
                   in_port_t *port)
{
    struct exanic_udp * restrict ctx = sock->ctx.udp;

    assert(ctx != NULL);

    *addr = exa_ip_get_src(&ctx->ip);
    *port = exa_udp_get_src(&ctx->udp);
}

void
exanic_udp_get_dest(struct exa_socket * restrict sock, in_addr_t *addr,
                    in_port_t *port, uint8_t *ttl)
{
    struct exanic_udp * restrict ctx = sock->ctx.udp;

    assert(ctx != NULL);

    *addr = exa_ip_get_dest(&ctx->ip);
    *port = exa_udp_get_dest(&ctx->udp);
    *ttl = exa_ip_get_ttl(&ctx->ip);
}

void
exanic_udp_set_src(struct exa_socket * restrict sock,
                   struct exanic_ip * restrict ip_ctx,
                   in_port_t port)
{
    struct exanic_udp * restrict ctx = sock->ctx.udp;

    assert(sock->state->tx_lock);
    assert(ctx != NULL);

    if (ip_ctx)
        exanic_ip_acquire_ref(ip_ctx);
    if (ctx->exanic_ctx)
        exanic_ip_release(ctx->exanic_ctx);
    ctx->exanic_ctx = ip_ctx;

    if (ip_ctx)
    {
        exa_eth_set_src(&ctx->eth, ip_ctx->eth_dev_addr, ip_ctx->vlan_id);
        exa_ip_set_src(&ctx->ip, ip_ctx->ifaddr.address);
    }
    exa_udp_set_src(&ctx->udp, port, exa_ip_addr_csum(&ctx->ip));
}

void
exanic_udp_set_dest(struct exa_socket * restrict sock,
                    in_addr_t addr, in_port_t port, uint8_t ttl)
{
    struct exanic_udp * restrict ctx = sock->ctx.udp;

    assert(sock->state->tx_lock);
    assert(ctx != NULL);

    exa_ip_set_dest(&ctx->ip, addr);
    exa_ip_set_ttl(&ctx->ip, ttl);
    exa_udp_set_dest(&ctx->udp, port, exa_ip_addr_csum(&ctx->ip));
    exa_dst_set_dest(&ctx->dst, addr);

    if (exa_dst_found(&ctx->dst))
        exa_eth_set_dest(&ctx->eth, ctx->dst.eth_addr);
}

void
exanic_udp_prepare(struct exa_socket * restrict sock)
{
    struct exanic_udp * restrict ctx = sock->ctx.udp;

    assert(sock->state->tx_lock);
    assert(ctx != NULL);

    /* Try to get destination MAC address from the cache */
    if (exa_dst_update(&ctx->dst))
        exa_eth_set_dest(&ctx->eth, ctx->dst.eth_addr);
}

/* Build headers and send UDP packet on an ExaNIC */
static inline void
__exanic_udp_send_iov(struct exanic_udp * restrict ctx,
                      const struct iovec *iov, size_t iovcnt,
                      size_t skip_len, size_t data_len)
{
    char hdr[MAX_HDR_LEN];
    char *hdr_ptr = hdr + MAX_HDR_LEN;
    size_t hdr_len = 0;

    exa_udp_build_hdr(&ctx->udp, &hdr_ptr, &hdr_len, iov, iovcnt, skip_len,
                      data_len);
    exanic_ip_send_iov(&ctx->ip, &ctx->eth, &ctx->dst, ctx->exanic_ctx,
                       &hdr_ptr, &hdr_len, iov, iovcnt, skip_len, data_len);
}

ssize_t
exanic_udp_send_iov(struct exa_socket * restrict sock,
                    const struct iovec *iov, size_t iovcnt)
{
    struct exanic_udp * restrict ctx = sock->ctx.udp;
    size_t data_len, i;

    assert(sock->state->tx_lock);
    assert(ctx != NULL);

    /* Calculate total data length */
    data_len = 0;
    for (i = 0; i < iovcnt; i++)
        data_len += iov[i].iov_len;

    __exanic_udp_send_iov(ctx, iov, iovcnt, 0, data_len);

    return data_len;
}

ssize_t
exanic_udp_send(struct exa_socket * restrict sock, const void *buf, size_t len)
{
    struct exanic_udp * restrict ctx = sock->ctx.udp;
    struct iovec iov;

    assert(sock->state->tx_lock);
    assert(ctx != NULL);

    iov.iov_base = (void *)buf;
    iov.iov_len = len;

    __exanic_udp_send_iov(ctx, &iov, 1, 0, len);

    return len;
}

/* Allocate a TCP connection on an ExaNIC */
int
exanic_tcp_alloc(struct exa_socket * restrict sock)
{
    struct exanic_tcp *ctx;

    assert(sock->state->rx_lock);
    assert(sock->state->tx_lock);
    assert(sock->ctx.tcp == NULL);

    /* Allocate new exanic_tcp context */
    ctx = malloc(sizeof(struct exanic_tcp));
    if (ctx == NULL)
        return -1;

    ctx->exanic_ctx = NULL;

    exa_eth_tx_init(&ctx->eth, ETH_P_IP);
    exa_ip_tx_init(&ctx->ip, IPPROTO_TCP);
    exa_tcp_conn_init(&ctx->tcp, sock->state);
    exa_dst_init(&ctx->dst);

    sock->ctx.tcp = ctx;

    return 0;
}

void
exanic_tcp_free(struct exa_socket * restrict sock)
{
    struct exanic_tcp * restrict ctx = sock->ctx.tcp;

    assert(exa_write_locked(&sock->lock));
    assert(ctx != NULL);

    exa_eth_tx_cleanup(&ctx->eth);
    exa_ip_tx_cleanup(&ctx->ip);
    exa_tcp_conn_cleanup(&ctx->tcp);
    exa_dst_cleanup(&ctx->dst);
    if (ctx->exanic_ctx)
        exanic_ip_release(ctx->exanic_ctx);
    free(ctx);

    sock->ctx.tcp = NULL;
}

/* Get the ExaNIC device and port number used for this socket */
void
exanic_tcp_get_device(struct exa_socket * restrict sock, char *dev,
                      size_t len, int *port_number)
{
    struct exanic_tcp * restrict ctx = sock->ctx.tcp;
    struct exanic_ip * restrict ip_ctx = ctx->exanic_ctx;

    assert(exa_read_locked(&sock->lock));
    assert(ctx != NULL);
    assert(ip_ctx != NULL);

    snprintf(dev, len, "%s", ip_ctx->device);
    *port_number = ip_ctx->port_number;
}

/* Put socket into LISTEN state */
void
exanic_tcp_listen(struct exa_socket * restrict sock, int backlog)
{
    struct exanic_tcp * restrict ctx = sock->ctx.tcp;

    exa_tcp_listen(&ctx->tcp);
}

/* Send or re-send a packet for moving to the current state */
static inline void
exanic_tcp_send_ctrl(struct exa_socket * restrict sock)
{
    struct exanic_tcp * restrict ctx = sock->ctx.tcp;
    char hdr[MAX_HDR_LEN];
    char *hdr_ptr = hdr + MAX_HDR_LEN;
    size_t hdr_len = 0;

    assert(ctx != NULL);

    /* Clear ack_pending flag because an ACK is about to be sent */
    exa_tcp_clear_ack_pending(&ctx->tcp);

    if (exa_tcp_build_ctrl(&ctx->tcp, &hdr_ptr, &hdr_len))
    {
        /* Send packet */
        exanic_ip_send_iov(&ctx->ip, &ctx->eth, &ctx->dst, ctx->exanic_ctx,
                           &hdr_ptr, &hdr_len, NULL, 0, 0, 0);
    }
}

void
exanic_tcp_connect(struct exa_socket * restrict sock,
                   struct exa_endpoint * restrict ep)
{
    struct exanic_tcp * restrict ctx = sock->ctx.tcp;
    struct exanic_ip * restrict ip_ctx = sock->listen_if;

    assert(ctx != NULL);
    assert(ip_ctx != NULL);
    assert(ctx->exanic_ctx == NULL);
    assert(!sock->connected);
    assert(exa_write_locked(&sock->lock));
    assert(sock->state->rx_lock);
    assert(sock->state->tx_lock);

    exanic_ip_acquire_ref(ip_ctx);
    ctx->exanic_ctx = ip_ctx;

    /* Prepare lower layers */
    exa_ip_set_src(&ctx->ip, ep->addr.local);
    exa_ip_set_dest(&ctx->ip, ep->addr.peer);

    exa_eth_set_src(&ctx->eth, ip_ctx->eth_dev_addr, ip_ctx->vlan_id);

    exa_dst_set_dest(&ctx->dst, ep->addr.peer);
    if (exa_dst_found(&ctx->dst))
        exa_eth_set_dest(&ctx->eth, ctx->dst.eth_addr);

    /* Initialise TCP connection state */
    exa_tcp_connect(&ctx->tcp, &ep->port, exa_ip_addr_csum(&ctx->ip));

    /* Send initial packet */
    exanic_tcp_send_ctrl(sock);

    /* Update socket ready state */
    exa_notify_update(sock);
}

/* Apply connection state of a newly accepted connection to a socket */
void
exanic_tcp_accept(struct exa_socket * restrict sock,
                  struct exa_endpoint * restrict ep,
                  struct exa_tcp_init_state * restrict tcp_state)
{
    struct exanic_tcp * restrict ctx = sock->ctx.tcp;
    struct exanic_ip * restrict ip_ctx = sock->listen_if;

    assert(ctx != NULL);
    assert(ip_ctx != NULL);
    assert(ctx->exanic_ctx == NULL);
    assert(!sock->connected);
    assert(exa_write_locked(&sock->lock));
    assert(sock->state->rx_lock);
    assert(sock->state->tx_lock);

    exanic_ip_acquire_ref(ip_ctx);
    ctx->exanic_ctx = ip_ctx;

    /* Prepare lower layers */
    exa_ip_set_src(&ctx->ip, ep->addr.local);
    exa_ip_set_dest(&ctx->ip, ep->addr.peer);

    exa_eth_set_src(&ctx->eth, ip_ctx->eth_dev_addr, ip_ctx->vlan_id);

    exa_dst_set_dest(&ctx->dst, ep->addr.peer);
    if (exa_dst_found(&ctx->dst))
        exa_eth_set_dest(&ctx->eth, ctx->dst.eth_addr);

    /* Set TCP connection state */
    exa_tcp_accept(&ctx->tcp, &ep->port, exa_ip_addr_csum(&ctx->ip), tcp_state);

    /* Update socket ready state */
    exa_notify_update(sock);
}

void
exanic_tcp_shutdown_write(struct exa_socket * restrict sock)
{
    struct exanic_tcp * restrict ctx = sock->ctx.tcp;

    assert(ctx != NULL);
    assert(sock->connected);
    assert(sock->state->tx_lock);

    /* State transition */
    exa_tcp_shutdown_write(&ctx->tcp);

    /* Send FIN packet */
    exanic_tcp_send_ctrl(sock);
}

/* Reset the connection */
void
exanic_tcp_reset(struct exa_socket * restrict sock)
{
    struct exanic_tcp * restrict ctx = sock->ctx.tcp;
    char hdr[MAX_HDR_LEN];
    char *hdr_ptr = hdr + MAX_HDR_LEN;
    size_t hdr_len = 0;

    assert(sock->state->tx_lock);
    assert(ctx != NULL);

    if (exa_tcp_build_rst(&ctx->tcp, &hdr_ptr, &hdr_len))
    {
        /* Send RST packet */
        exanic_ip_send_iov(&ctx->ip, &ctx->eth, &ctx->dst, ctx->exanic_ctx,
                           &hdr_ptr, &hdr_len, NULL, 0, 0, 0);
    }

    /* Transition to CLOSED state */
    exa_tcp_reset(&ctx->tcp);
}

bool
exanic_tcp_connecting(struct exa_socket * restrict sock)
{
    struct exanic_tcp * restrict ctx = sock->ctx.tcp;

    return exa_tcp_connecting(&ctx->tcp);
}

bool
exanic_tcp_listening(struct exa_socket * restrict sock)
{
    struct exanic_tcp * restrict ctx = sock->ctx.tcp;

    return exa_tcp_listening(&ctx->tcp);
}

/* Returns true if write() will not block
 * This includes states where write() would return an error immediately */
bool
exanic_tcp_writeable(struct exa_socket * restrict sock)
{
    struct exanic_tcp * restrict ctx = sock->ctx.tcp;
    uint32_t seq;
    size_t len;

    if (exa_tcp_connecting(&ctx->tcp))
        return false;

    if (exa_tcp_max_pkt_len(&ctx->tcp, &seq, &len) == -1)
        return true;

    return (len > 0);
}

bool
exanic_tcp_write_closed(struct exa_socket *sock)
{
    struct exanic_tcp * restrict ctx = sock->ctx.tcp;

    return exa_tcp_write_closed(&ctx->tcp);
}

ssize_t
exanic_tcp_send_iov(struct exa_socket * restrict sock,
                    const struct iovec *iov, size_t iovcnt,
                    size_t skip_len, size_t data_len)
{
    struct exanic_tcp * restrict ctx = sock->ctx.tcp;
    char hdr[MAX_HDR_LEN];
    char *hdr_ptr = hdr + MAX_HDR_LEN;
    size_t hdr_len = 0;
    size_t max_len;
    size_t send_len;
    uint32_t send_seq;

    assert(sock->state->tx_lock);
    assert(ctx != NULL);

    /* Send up to the maximum for a single packet */
    if (exa_tcp_max_pkt_len(&ctx->tcp, &send_seq, &max_len) == -1)
        return -1;

    /* If we can't send any data, don't send anything unless we are
     * explicitly sending a zero-length packet */
    if (max_len == 0 && data_len != 0)
        return 0;

    send_len = data_len < max_len ? data_len : max_len;

    /* Clear ack_pending flag because an ACK is about to be sent */
    exa_tcp_clear_ack_pending(&ctx->tcp);

    /* Build TCP header */
    exa_tcp_build_hdr(&ctx->tcp, &hdr_ptr, &hdr_len, send_seq,
                      iov, iovcnt, skip_len, send_len);

    /* Build IP header and send packet */
    exanic_ip_send_iov(&ctx->ip, &ctx->eth, &ctx->dst, ctx->exanic_ctx,
                       &hdr_ptr, &hdr_len, iov, iovcnt, skip_len, send_len);

    /* Update retransmit buffer and sequence numbers */
    exa_tcp_tx_buffer_write(sock, iov, iovcnt, skip_len, send_len);

    return send_len;
}

ssize_t
exanic_tcp_send(struct exa_socket * restrict sock, const void *buf, size_t len)
{
    struct iovec iov;

    assert(sock->state->tx_lock);

    iov.iov_base = (void *)buf;
    iov.iov_len = len;

    return exanic_tcp_send_iov(sock, &iov, 1, 0, len);
}

ssize_t
exanic_tcp_build_hdr(struct exa_socket * restrict sock, void *buf, size_t len)
{
    struct exanic_tcp * restrict ctx = sock->ctx.tcp;
    char hdr[MAX_HDR_LEN];
    char *hdr_ptr = hdr + MAX_HDR_LEN;
    size_t hdr_len = 0;
    size_t max_len;
    uint32_t send_seq;

    assert(sock->state->tx_lock);
    assert(ctx != NULL);

    /* Try to get destination MAC address from the cache */
    if (exa_dst_update(&ctx->dst))
        exa_eth_set_dest(&ctx->eth, ctx->dst.eth_addr);

    if (!exa_dst_found(&ctx->dst))
    {
        /* Not found, need to do a neighbour lookup */
        exa_sys_dst_request(ctx->dst.ip_addr, NULL, NULL);
        return -1;
    }

    /* Retrieve the current send sequence number */
    if (exa_tcp_max_pkt_len(&ctx->tcp, &send_seq, &max_len) == -1)
        return -1;

    /* Build headers for a zero-length packet */
    exa_tcp_build_hdr(&ctx->tcp, &hdr_ptr, &hdr_len, send_seq, NULL, 0, 0, 0);
    exa_ip_build_hdr(&ctx->ip, &hdr_ptr, &hdr_len, NULL, 0, 0, 0);
    exa_eth_build_hdr(&ctx->eth, &hdr_ptr, &hdr_len, NULL, 0, 0, 0);

    memcpy(buf, hdr_ptr, hdr_len < len ? hdr_len : len);

    /* Return the actual size of the header */
    return hdr_len;
}
