#ifndef EXASOCK_UDP_QUEUE_H
#define EXASOCK_UDP_QUEUE_H

/* Add header and footer size and align to next 64 byte boundary */
static inline size_t
exa_udp_queue_entry_size(size_t len)
{
    return (len + sizeof(struct exa_udp_queue_hdr) +
            sizeof(struct exa_udp_queue_ftr) + 63) & ~63;
}

/* Allocate space in packet receive queue */
static inline char *
exa_udp_queue_write_alloc(struct exa_socket * restrict sock,
                          struct exa_endpoint * restrict ep,
                          size_t max_pkt_len)
{
    struct exa_socket_state * restrict state = sock->state;
    volatile struct exa_udp_state *udp = &state->p.udp;
    size_t reserve_len = exa_udp_queue_entry_size(max_pkt_len);
    uint32_t next_write = udp->next_write;
    uint32_t next_read = udp->next_read;
    struct exa_udp_queue_hdr *hdr;

    if (next_write + reserve_len >= state->rx_buffer_size)
    {
        /* Wrap to beginning of buffer */
        if (next_read > next_write || next_read <= reserve_len)
        {
            /* Cannot wrap */
            return NULL;
        }

        *(uint32_t *)(sock->rx_buffer + next_write) = 0;
        next_write = 0;
    }
    else if (next_read > next_write && next_read <= next_write + reserve_len)
    {
        /* Not enough space */
        return NULL;
    }

    udp->next_write = next_write;

    hdr = (struct exa_udp_queue_hdr *)(sock->rx_buffer + next_write);
    hdr->local_addr = ep->addr.local;
    hdr->peer_addr = ep->addr.peer;
    hdr->local_port = ep->port.local;
    hdr->peer_port = ep->port.peer;

    return sock->rx_buffer + next_write + sizeof(struct exa_udp_queue_hdr);
}

/* Make the new packet available for readers */
static inline void
exa_udp_queue_write_commit(struct exa_socket * restrict sock, size_t data_len,
                           const struct exa_timestamp ts[2])
{
    struct exa_socket_state * restrict state = sock->state;
    volatile struct exa_udp_state *udp = &state->p.udp;
    uint32_t next_write = udp->next_write;
    struct exa_udp_queue_hdr * restrict hdr =
        (struct exa_udp_queue_hdr *)(sock->rx_buffer + next_write);
    struct exa_udp_queue_ftr * restrict ftr =
        (struct exa_udp_queue_ftr *)(sock->rx_buffer + next_write +
                exa_udp_queue_entry_size(data_len) -
                sizeof(struct exa_udp_queue_ftr));

    hdr->len = data_len;

    if (ts != NULL)
    {
        ftr->sw_ts_sec = ts[0].sec;
        ftr->sw_ts_nsec = ts[0].nsec;
        ftr->hw_ts_sec = ts[1].sec;
        ftr->hw_ts_nsec = ts[1].nsec;
    }

    udp->next_write = next_write + exa_udp_queue_entry_size(data_len);
    assert(udp->next_write < state->rx_buffer_size);
}

static inline void
exa_udp_queue_write_abort(struct exa_socket * restrict sock)
{
}

static inline bool
exa_udp_queue_ready(struct exa_socket * restrict sock)
{
    struct exa_socket_state * restrict state = sock->state;
    volatile struct exa_udp_state *udp = &state->p.udp;
    uint32_t next_write = udp->next_write;
    uint32_t next_read = udp->next_read;

    if (next_read > next_write &&
        *(uint32_t *)(sock->rx_buffer + next_read) == 0)
    {
        /* Wrap around */
        next_read = 0;
    }

    return next_read != next_write;
}

/* Get a pointer to the next packet in the receive queue */
static inline int
exa_udp_queue_read_begin(struct exa_socket * restrict sock,
                         struct exa_endpoint * restrict ep,
                         char **pkt, size_t *len,
                         struct exa_timestamp ts[2])
{
    struct exa_socket_state * restrict state = sock->state;
    volatile struct exa_udp_state *udp = &state->p.udp;
    uint32_t next_write = udp->next_write;
    uint32_t next_read;
    struct exa_udp_queue_hdr *hdr;
    struct exa_udp_queue_ftr *ftr;

    next_read = udp->next_read;

    if (next_read > next_write &&
        *(uint32_t *)(sock->rx_buffer + next_read) == 0)
    {
        /* Wrap around */
        udp->next_read = next_read = 0;
    }

    if (next_read == next_write)
    {
        /* No packet available */
        return -1;
    }

    hdr = (struct exa_udp_queue_hdr *)(sock->rx_buffer + next_read);

    if (ep != NULL)
    {
        ep->addr.local = hdr->local_addr;
        ep->addr.peer = hdr->peer_addr;
        ep->port.local = hdr->local_port;
        ep->port.peer = hdr->peer_port;
    }

    *pkt = sock->rx_buffer + next_read + sizeof(struct exa_udp_queue_hdr);
    *len = hdr->len;

    if (ts != NULL)
    {
        /* Get data from footer */
        ftr = (struct exa_udp_queue_ftr *)(sock->rx_buffer + next_read +
                exa_udp_queue_entry_size(hdr->len) -
                sizeof(struct exa_udp_queue_ftr));

        ts[0].sec = ftr->sw_ts_sec;
        ts[0].nsec = ftr->sw_ts_nsec;
        ts[1].sec = ftr->hw_ts_sec;
        ts[1].nsec = ftr->hw_ts_nsec;
    }

    return 0;
}

static inline void
exa_udp_queue_read_end(struct exa_socket * restrict sock)
{
    struct exa_socket_state * restrict state = sock->state;
    volatile struct exa_udp_state *udp = &state->p.udp;
    uint32_t next_read = udp->next_read;
    struct exa_udp_queue_hdr *hdr;

    hdr = (struct exa_udp_queue_hdr *)(sock->rx_buffer + next_read);
    udp->next_read = next_read + exa_udp_queue_entry_size(hdr->len);
}

static inline void
exa_udp_queue_read_abort(struct exa_socket * restrict sock)
{
}

#endif /* EXASOCK_UDP_QUEUE_H */
