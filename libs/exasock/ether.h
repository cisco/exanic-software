#ifndef EXASOCK_ETHER_H
#define EXASOCK_ETHER_H

struct vlan_hdr
{
    uint16_t h_vlan_tci;
    uint16_t h_vlan_proto;
};
#define VLAN_HDR_VID_MASK   0x0FFF

/* Return true if address is broadcast or multicast */
static inline bool
is_multicast_eth_addr(const uint8_t *addr)
{
    return (addr[0] & 0x01) != 0;
}

struct exa_eth
{
    uint8_t dev_addr[ETH_ALEN];
    uint16_t vlan_id;
};

struct exa_eth_tx
{
    struct {
        struct ethhdr eth;
        struct vlan_hdr vlan;
    } hdr;
};

static inline void
exa_eth_init(struct exa_eth * restrict ctx,
             const uint8_t eth_dev_addr[ETH_ALEN], uint16_t vlan_id)
{
    memcpy(ctx->dev_addr, eth_dev_addr, ETH_ALEN);
    ctx->vlan_id = vlan_id;
}

static inline void
exa_eth_cleanup(struct exa_eth * restrict ctx)
{
}

static inline void
exa_eth_tx_init(struct exa_eth_tx * restrict ctx, uint16_t eth_proto)
{
    memset(ctx->hdr.eth.h_dest, 0xFF, ETH_ALEN);
    memset(ctx->hdr.eth.h_source, 0xFF, ETH_ALEN);
    ctx->hdr.eth.h_proto = htons(eth_proto);
}

static inline void
exa_eth_tx_cleanup(struct exa_eth_tx * restrict ctx)
{
}

static inline void
exa_eth_set_src(struct exa_eth_tx * restrict ctx, uint8_t src_addr[ETH_ALEN], uint16_t vlan_id)
{
    memcpy(ctx->hdr.eth.h_source, src_addr, ETH_ALEN);
    if (vlan_id)
    {
        ctx->hdr.vlan.h_vlan_tci = vlan_id;
        ctx->hdr.vlan.h_vlan_proto = ctx->hdr.eth.h_proto;
        ctx->hdr.eth.h_proto = htons(ETH_P_8021Q);
    }
}

static inline void
exa_eth_set_dest(struct exa_eth_tx * restrict ctx, uint8_t dest_addr[ETH_ALEN])
{
    memcpy(ctx->hdr.eth.h_dest, dest_addr, ETH_ALEN);
}

/* hdr points to the VLAN ID field */
static inline int
exa_eth_parse_vlan_hdr(struct exa_eth * restrict ctx, char *hdr,
                       char *read_end, char ** restrict next_hdr)
{
    const struct vlan_hdr * restrict h = (const struct vlan_hdr *)hdr;

    if ((read_end - hdr) < sizeof(struct vlan_hdr))
        return -1;

    *next_hdr = hdr + sizeof(struct vlan_hdr);

    if ((h->h_vlan_tci & htons(VLAN_HDR_VID_MASK)) == ctx->vlan_id)
        return h->h_vlan_proto;
    else
        return -1;
}

static inline int
exa_eth_parse_hdr(struct exa_eth * restrict ctx, char *hdr,
                  char *read_end, char ** restrict next_hdr)
{
    const struct ethhdr * restrict h = (const struct ethhdr *)hdr;

    if ((read_end - hdr) < sizeof(struct ethhdr))
        return -1;

    /* Check MAC address matches, or is multicast or broadcast */
    if (memcmp(h->h_dest, ctx->dev_addr, ETH_ALEN) != 0 &&
        !is_multicast_eth_addr(h->h_dest))
        return -1;

    *next_hdr = hdr + sizeof(struct ethhdr);

    /* Check for VLAN tag */
    if (h->h_proto == htons(ETH_P_8021Q))
        return exa_eth_parse_vlan_hdr(ctx, *next_hdr, read_end, next_hdr);
    else if (ctx->vlan_id != 0)
        return -1;

    return h->h_proto;
}

static inline void
exa_eth_build_hdr(struct exa_eth_tx * restrict ctx, char ** restrict hdr,
                  size_t * restrict hdr_len)
{
    if (ctx->hdr.eth.h_proto == htons(ETH_P_8021Q))
    {
        /* Header including VLAN tag */
        char * restrict h = *hdr - sizeof(ctx->hdr);

        memcpy(h, &ctx->hdr, sizeof(ctx->hdr));

        *hdr -= sizeof(ctx->hdr);
        *hdr_len += sizeof(ctx->hdr);
    }
    else
    {
        /* Header without VLAN tag */
        char * restrict h = *hdr - sizeof(ctx->hdr.eth);

        memcpy(h, &ctx->hdr.eth, sizeof(ctx->hdr.eth));

        *hdr -= sizeof(ctx->hdr.eth);
        *hdr_len += sizeof(ctx->hdr.eth);
    }
}

#endif /* EXASOCK_ETHER_H */
