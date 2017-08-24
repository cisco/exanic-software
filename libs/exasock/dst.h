#ifndef EXASOCK_DST_H
#define EXASOCK_DST_H

struct exa_dst
{
    in_addr_t ip_addr;
    unsigned int idx;
    uint8_t gen_id;
    uint8_t eth_addr[ETH_ALEN];

    bool no_lookup;
};

static inline void
exa_dst_init(struct exa_dst * restrict ctx)
{
    ctx->ip_addr = htonl(INADDR_ANY);
    ctx->no_lookup = true;
    ctx->idx = ~0;
}

static inline void
exa_dst_cleanup(struct exa_dst * restrict ctx)
{
}

static inline void
exa_dst_set_dest(struct exa_dst * restrict ctx, in_addr_t addr)
{
    ctx->ip_addr = addr;
    ctx->idx = ~0;

    if (IN_MULTICAST(ntohl(addr)))
    {
        ctx->no_lookup = true;
        ctx->eth_addr[0] = 0x01;
        ctx->eth_addr[1] = 0x00;
        ctx->eth_addr[2] = 0x5E;
        ctx->eth_addr[3] = (ntohl(addr) & 0x7F0000) >> 16;
        ctx->eth_addr[4] = (ntohl(addr) & 0xFF00) >> 8;
        ctx->eth_addr[5] = (ntohl(addr) & 0xFF);
    }
    else
        ctx->no_lookup = false;
}

static inline volatile struct exa_dst_entry *
__exa_dst_lookup(in_addr_t ip_addr, unsigned int *idx_ptr, uint8_t *gen_id_ptr)
{
    unsigned int hash, idx;

    hash = idx = exa_dst_hash(ip_addr) & (exa_dst_table_size - 1);
    while (true)
    {
        volatile struct exa_dst_entry *entry = &exa_dst_table[idx];
        uint8_t gen_id = entry->gen_id;
        uint8_t state = entry->state;

        if (state == EXA_DST_ENTRY_VALID && entry->dst_addr == ip_addr)
        {
            *gen_id_ptr = gen_id;
            *idx_ptr = idx;
            return entry;
        }

        if (state == EXA_DST_ENTRY_EMPTY)
            return NULL;

        idx = (idx + 1) & (exa_dst_table_size - 1);
        if (idx == hash)
            return NULL;
    }
}

/* Return true if entry has been updated, false if unchanged */
static inline bool
exa_dst_update(struct exa_dst * restrict ctx)
{
    volatile struct exa_dst_entry *entry;
    unsigned int idx;
    uint8_t gen_id;

    if (ctx->no_lookup)
        return false;

    if (ctx->idx != ~0 &&
        exa_dst_table[ctx->idx].state == EXA_DST_ENTRY_VALID &&
        exa_dst_table[ctx->idx].gen_id == ctx->gen_id)
    {
        /* Entry in hash table has not changed */
        exa_dst_used_flags[ctx->idx] = 1;
        return false;
    }

    /* Search hash table for entry */
    entry = __exa_dst_lookup(ctx->ip_addr, &idx, &gen_id);
    if (entry)
    {
        memcpy(ctx->eth_addr, (void *)entry->eth_addr, ETH_ALEN);

        /* Check that entry did not get overwritten while we were reading */
        if (entry->gen_id != gen_id)
            return false;

        ctx->idx = idx;
        ctx->gen_id = gen_id;
        exa_dst_used_flags[idx] = 1;
        return true;
    }
    else
        return false;
}

static inline bool
exa_dst_found(struct exa_dst * restrict ctx)
{
    return ctx->no_lookup || ctx->idx != ~0;
}

static inline int
exa_dst_lookup_src(in_addr_t dst_addr, in_addr_t *src_addr)
{
    volatile struct exa_dst_entry *entry;
    unsigned int idx;
    uint8_t gen_id;

    /* Search hash table for entry */
    entry = __exa_dst_lookup(dst_addr, &idx, &gen_id);
    if (entry)
    {
        if (src_addr != NULL)
            *src_addr = entry->src_addr;

        /* Check that entry did not get overwritten while we were reading */
        if (entry->gen_id == gen_id)
        {
            exa_dst_used_flags[idx] = 1;
            return 0;
        }
    }

    /* Send a query the kernel module */
    return exa_sys_dst_request(dst_addr, src_addr, NULL);
}

#endif /* EXASOCK_DST_H */
