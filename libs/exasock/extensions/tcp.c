#include "../common.h"

#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <sched.h>
#include <time.h>

#include <exasock/extensions.h>

#include "../kernel/api.h"
#include "../kernel/consts.h"
#include "../kernel/structs.h"
#include "../lock.h"
#include "../rwlock.h"
#include "../structs.h"
#include "../exanic.h"
#include "../checksum.h"
#include "../sys.h"
#include "../dst.h"
#include "../tcp_buffer.h"
#include "../tcp.h"

__attribute__((visibility("default")))
int
exasock_loaded(void)
{
    return 1;
}

__attribute__((visibility("default")))
int
exasock_tcp_get_device(int fd, char *dev, size_t dev_len, int *port_num)
{
    struct exa_socket * restrict sock = exa_socket_get(fd);
    int ret;

    if (sock == NULL)
    {
        errno = EOPNOTSUPP;
        ret = -1;
    }
    else
    {
        exa_read_lock(&sock->lock);

        if (!sock->bypass || sock->domain != AF_INET ||
            sock->type != SOCK_STREAM)
        {
            errno = EOPNOTSUPP;
            ret = -1;
        }
        else
        {
            exanic_tcp_get_device(sock, dev, dev_len, port_num);
            ret = 0;
        }

        exa_read_unlock(&sock->lock);
    }

    return ret;
}

__attribute__((visibility("default")))
ssize_t
exasock_tcp_build_header(int fd, void *buf, size_t len, size_t offset,
                         int flags)
{
    struct exa_socket * restrict sock = exa_socket_get(fd);
    ssize_t ret;

    if (sock == NULL)
    {
        errno = EOPNOTSUPP;
        ret = -1;
    }
    else
    {
        exa_read_lock(&sock->lock);

        if (!sock->bypass || sock->domain != AF_INET ||
            sock->type != SOCK_STREAM)
        {
            errno = EOPNOTSUPP;
            ret = -1;
        }
        else if (!sock->connected)
        {
            errno = ENOTCONN;
            ret = -1;
        }
        else
        {
            /* Generate all headers */
            exa_lock(&sock->state->tx_lock);
            ret = exanic_tcp_build_hdr(sock, buf, len);
            exa_unlock(&sock->state->tx_lock);

            /* Error indicates that the neighbour lookup is not yet complete */
            if (ret == -1)
                errno = EAGAIN;
        }

        exa_read_unlock(&sock->lock);
    }

    return ret;
}

__attribute__((visibility("default")))
int
exasock_tcp_set_length(void *hdr, size_t hdr_len, size_t data_len)
{
    /* Assume IP and TCP headers do not have added options */
    struct ip * restrict ih = (struct ip *)
        (hdr + hdr_len - sizeof(struct tcphdr) - sizeof(struct ip));

    /* Set IP length field and calculate IP checksum */
    uint16_t old_len = ih->ip_len;
    ih->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + data_len);
    ih->ip_sum = ~csum_pack32((uint32_t)(uint16_t)~ih->ip_sum
                     + (uint16_t)~old_len + ih->ip_len); /* RFC1624 */
    return 0;
}

__attribute__((visibility("default")))
int
exasock_tcp_calc_checksum(void *hdr, size_t hdr_len,
                          const void *data, size_t data_len)
{
    /* Assume IP and TCP headers do not have added options */
    struct ip * restrict ih = (struct ip *)
        (hdr + hdr_len - sizeof(struct tcphdr) - sizeof(struct ip));
    struct tcphdr * restrict th = (struct tcphdr *)
        (hdr + hdr_len - sizeof(struct tcphdr));
    uint64_t tcp_csum;

    /* Calculate TCP checksum */
    th->th_sum = 0;
    tcp_csum = (uint64_t)ih->ip_src.s_addr + ih->ip_dst.s_addr +
               htons(IPPROTO_TCP) + htons(sizeof(struct tcphdr) + data_len);
    tcp_csum = csum_part(th, sizeof(struct tcphdr), tcp_csum);
    tcp_csum = csum_part(data, data_len, tcp_csum);
    th->th_sum = ~csum_pack(tcp_csum);

    return 0;
}

__attribute__((visibility("default")))
int
exasock_tcp_send_advance(int fd, const void *data, size_t data_len)
{
    struct exa_socket * restrict sock = exa_socket_get(fd);
    struct iovec iov;
    int ret;

    if (sock == NULL)
    {
        errno = EOPNOTSUPP;
        ret = -1;
    }
    else
    {
        exa_read_lock(&sock->lock);

        if (!sock->bypass || sock->domain != AF_INET ||
            sock->type != SOCK_STREAM)
        {
            errno = EOPNOTSUPP;
            ret = -1;
        }
        else if (!sock->connected)
        {
            errno = ENOTCONN;
            ret = -1;
        }
        else
        {
            iov.iov_base = (void *)data;
            iov.iov_len = data_len;

            /* Write to retransmit buffer and update sequence numbers */
            exa_lock(&sock->state->tx_lock);
            exa_tcp_tx_buffer_write(sock, &iov, 1, 0, data_len);
            exa_unlock(&sock->state->tx_lock);

            ret = 0;
        }

        exa_read_unlock(&sock->lock);
    }

    return ret;
}

