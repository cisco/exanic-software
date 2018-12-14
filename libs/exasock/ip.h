#ifndef EXASOCK_IP_H
#define EXASOCK_IP_H

/* Partial checksum of address */
static inline uint64_t
ipaddr_csum(struct exa_endpoint_ipaddr * restrict addr)
{
    return (uint64_t)addr->peer + (uint64_t)addr->local;
}

struct exa_ip
{
    in_addr_t address;
    in_addr_t broadcast;
    in_addr_t netmask;
};

struct exa_ip_tx
{
    struct ip hdr;
};

static inline void
exa_ip_init(struct exa_ip * restrict ctx, in_addr_t address,
            in_addr_t broadcast, in_addr_t netmask)
{
    ctx->address = address;
    ctx->broadcast = broadcast;
    ctx->netmask = netmask;
}

static inline void
exa_ip_cleanup(struct exa_ip * restrict ctx)
{
}

static inline void
exa_ip_tx_init(struct exa_ip_tx * restrict ctx, uint8_t ip_proto)
{
    ctx->hdr.ip_v = 4;
    ctx->hdr.ip_hl = sizeof(struct ip) / 4;
    ctx->hdr.ip_tos = 0;
    ctx->hdr.ip_len = 0;
    ctx->hdr.ip_id = 0;
    ctx->hdr.ip_off = htons(IP_DF);
    ctx->hdr.ip_ttl = IPDEFTTL;
    ctx->hdr.ip_p = ip_proto;
    ctx->hdr.ip_sum = 0;
    ctx->hdr.ip_src.s_addr = htonl(INADDR_ANY);
    ctx->hdr.ip_dst.s_addr = htonl(INADDR_ANY);
}

static inline void
exa_ip_tx_cleanup(struct exa_ip_tx * restrict ctx)
{
}

static inline in_addr_t
exa_ip_get_src(struct exa_ip_tx * restrict ctx)
{
    return ctx->hdr.ip_src.s_addr;
}

static inline in_addr_t
exa_ip_get_dest(struct exa_ip_tx * restrict ctx)
{
    return ctx->hdr.ip_dst.s_addr;
}

static inline uint8_t
exa_ip_get_ttl(struct exa_ip_tx * restrict ctx)
{
    return ctx->hdr.ip_ttl;
}

static inline void
exa_ip_set_src(struct exa_ip_tx * restrict ctx, in_addr_t addr)
{
    ctx->hdr.ip_src.s_addr = addr;
}

static inline void
exa_ip_set_dest(struct exa_ip_tx * restrict ctx, in_addr_t addr)
{
    ctx->hdr.ip_dst.s_addr = addr;
}

static inline void
exa_ip_set_ttl(struct exa_ip_tx * restrict ctx, uint8_t ttl)
{
    ctx->hdr.ip_ttl = ttl;
}

/* Partial checksum of currently configured address */
static inline uint64_t
exa_ip_addr_csum(struct exa_ip_tx * restrict ctx)
{
    return (uint64_t)ctx->hdr.ip_src.s_addr + (uint64_t)ctx->hdr.ip_dst.s_addr;
}

static inline int
exa_ip_parse_hdr(struct exa_ip * restrict ctx,
                 struct exa_endpoint_ipaddr * restrict addr,
                 char *hdr, char *read_end,
                 char ** restrict next_hdr, size_t * restrict next_len)
{
    const struct ip * restrict h = (const struct ip *)hdr;

    if ((read_end - hdr) < sizeof(struct ip))
        return -1;

    /* IPv4 only */
    if (h->ip_v != 4)
        return -1;

    /* Check if IP address matches, or is broadcast or multicast */
    if (h->ip_dst.s_addr != ctx->address &&
        !IN_MULTICAST(ntohl(h->ip_dst.s_addr)) &&
        h->ip_dst.s_addr != htonl(INADDR_BROADCAST) &&
        h->ip_dst.s_addr != ctx->broadcast)
        return -1;

    /* Checksum */
    if (csum(h, h->ip_hl * 4, 0) != 0xFFFF)
        return -1;

    /* Drop IP fragments */
    if (h->ip_off & htons(IP_MF | IP_OFFMASK))
        return -1;

    *next_hdr = hdr + h->ip_hl * 4;
    *next_len = ntohs(h->ip_len) - (h->ip_hl * 4);

    addr->peer = h->ip_src.s_addr;
    addr->local = h->ip_dst.s_addr;

    return h->ip_p;
}

static inline void
exa_ip_build_hdr(struct exa_ip_tx * restrict ctx, char ** restrict hdr,
                 size_t * restrict hdr_len, size_t data_len)
{
    struct ip * restrict h = (struct ip *)(*hdr - sizeof(struct ip));

    memcpy(h, &ctx->hdr, sizeof(struct ip));
    h->ip_len = htons(*hdr_len + data_len + sizeof(struct ip));
    h->ip_sum = ~csum(h, sizeof(struct ip), 0);

    *hdr -= sizeof(struct ip);
    *hdr_len += sizeof(struct ip);
}

#endif /* EXASOCK_IP_H */
