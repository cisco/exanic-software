#ifndef EXASOCK_UDP_H
#define EXASOCK_UDP_H

extern struct exa_hashtable __exa_udp_sockfds;

struct exa_udp_tx
{
    struct udphdr hdr;

    /* Partial checksum of the pseudo header without the length field
     * plus the UDP header without the length and checksum fields */
    uint64_t partial_csum;
};

static inline void
exa_udp_tx_init(struct exa_udp_tx * restrict ctx)
{
    /* Prepare cached header and partial checksum */
    ctx->hdr.uh_sport = 0;
    ctx->hdr.uh_dport = 0;
    ctx->hdr.uh_ulen = 0;
    ctx->hdr.uh_sum = 0;
    ctx->partial_csum = csum(&ctx->hdr, sizeof(struct udphdr),
                             IPPROTO_UDP << 8);
}

static inline void
exa_udp_tx_cleanup(struct exa_udp_tx * restrict ctx)
{
}

static inline in_port_t
exa_udp_get_src(struct exa_udp_tx * restrict ctx)
{
    return ctx->hdr.uh_sport;
}

static inline in_port_t
exa_udp_get_dest(struct exa_udp_tx * restrict ctx)
{
    return ctx->hdr.uh_dport;
}

static inline void
exa_udp_set_src(struct exa_udp_tx * restrict ctx, in_port_t port,
                uint64_t addr_csum)
{
    /* Update cached header and partial checksum */
    ctx->hdr.uh_sport = port;
    ctx->partial_csum = csum(&ctx->hdr, sizeof(struct udphdr),
                             addr_csum + (IPPROTO_UDP << 8));
}

static inline void
exa_udp_set_dest(struct exa_udp_tx * restrict ctx, in_port_t port,
                 uint64_t addr_csum)
{
    /* Update cached header and partial checksum */
    ctx->hdr.uh_dport = port;
    ctx->partial_csum = csum(&ctx->hdr, sizeof(struct udphdr),
                             addr_csum + (IPPROTO_UDP << 8));
}

static inline int
exa_udp_parse_hdr(char *hdr, char *read_end, size_t pkt_len, uint64_t addr_csum,
                  struct exa_endpoint_port * restrict port,
                  char ** restrict data_begin, size_t * restrict data_len,
                  uint64_t * restrict csum)
{
    const struct udphdr * restrict h = (struct udphdr *)hdr;

    if ((read_end - hdr) < sizeof(struct udphdr))
        return -1;

    if (pkt_len < ntohs(h->uh_ulen))
        return -1;

    if (ntohs(h->uh_ulen) < sizeof(struct udphdr))
        return -1;

    /* Calculate checksum of pseudo-header and header */
    *csum = csum_part(hdr, sizeof(struct udphdr),
                      addr_csum + (IPPROTO_UDP << 8) + h->uh_ulen);

    *data_begin = hdr + sizeof(struct udphdr);
    *data_len = ntohs(h->uh_ulen) - sizeof(struct udphdr);

    port->peer = h->uh_sport;
    port->local = h->uh_dport;

    return 0;
}

static inline int
exa_udp_validate_csum(char *hdr, char *hdr_end, uint64_t * restrict csum)
{
    const struct udphdr * restrict h = (struct udphdr *)hdr;

    /* Check checksum */
    if (h->uh_sum != 0 && csum_pack(*csum) != 0xFFFF)
        return -1;

    return 0;
}

static inline void
exa_udp_insert(int fd)
{
    exa_hashtable_ucast_insert(&__exa_udp_sockfds, fd);
}

static inline void
exa_udp_remove(int fd)
{
    exa_hashtable_ucast_remove(&__exa_udp_sockfds, fd);
}

static inline void
exa_udp_mcast_insert(int fd, struct exa_mcast_endpoint * restrict mc_ep)
{
    exa_hashtable_mcast_insert(&__exa_udp_sockfds, fd, mc_ep);
}

static inline void
exa_udp_mcast_insert_all(int fd)
{
    struct exa_socket *esk = exa_socket_get(fd);
    struct exa_mcast_membership *tmp_memb;

    assert(esk != NULL);

    for (tmp_memb = esk->ip_memberships; tmp_memb != NULL;
         tmp_memb = tmp_memb->next)
    {
        exa_udp_mcast_insert(fd, &tmp_memb->mcast_ep);
    }
}

static inline void
exa_udp_mcast_remove(int fd, struct exa_mcast_endpoint * restrict mc_ep)
{
    exa_hashtable_mcast_remove(&__exa_udp_sockfds, fd, mc_ep);
}

static inline void
exa_udp_mcast_remove_all(int fd)
{
    struct exa_socket *esk = exa_socket_get(fd);
    struct exa_mcast_membership *tmp_memb;

    assert(esk != NULL);

    for (tmp_memb = esk->ip_memberships; tmp_memb != NULL;
         tmp_memb = tmp_memb->next)
    {
        exa_udp_mcast_remove(fd, &tmp_memb->mcast_ep);
    }
}

static inline int
exa_udp_lookup(struct exa_endpoint * restrict ep, in_addr_t if_addr)
{
    if (IN_MULTICAST(ntohl(ep->addr.local)))
        return exa_hashtable_mcast_lookup(&__exa_udp_sockfds, ep, if_addr);

    return exa_hashtable_ucast_lookup(&__exa_udp_sockfds, ep);
}

static inline void
exa_udp_build_hdr(struct exa_udp_tx * restrict ctx, char ** restrict hdr,
                  size_t * restrict hdr_len, const struct iovec * restrict iov,
                  size_t iovcnt, size_t skip_len, size_t data_len)
{
    struct udphdr * restrict h = (struct udphdr *)(*hdr - sizeof(struct udphdr));

    memcpy(h, &ctx->hdr, sizeof(struct udphdr));
    h->uh_ulen = htons(*hdr_len + data_len + sizeof(struct udphdr));
    h->uh_sum = ~csum_iov(iov, iovcnt, skip_len, data_len,
                          ctx->partial_csum + (2 * h->uh_ulen));

    *hdr -= sizeof(struct udphdr);
    *hdr_len += sizeof(struct udphdr);
}

#endif /* EXASOCK_UDP_H */
