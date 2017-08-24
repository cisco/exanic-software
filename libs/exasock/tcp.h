#ifndef EXASOCK_TCP_H
#define EXASOCK_TCP_H

#define EXA_TCP_RETRANSMIT_NS 1000000000

extern struct exa_hashtable __exa_tcp_sockfds;

struct exa_tcp_conn
{
    struct tcphdr hdr;

    /* Partial checksum of the pseudo header without the length field */
    uint64_t ph_csum;

    uint64_t timeout;
    uint32_t timeout_send_ack;

    struct exa_socket_state *state;
};

static inline void
exa_tcp_conn_init(struct exa_tcp_conn * restrict ctx,
                  struct exa_socket_state * restrict state)
{
    memset(&ctx->hdr, 0, sizeof(struct tcphdr));
    ctx->ph_csum = 0;
    ctx->state = state;
}

static inline void
exa_tcp_conn_cleanup(struct exa_tcp_conn * restrict ctx)
{
}

/* Calculate the size of the largest packet that can be sent right now,
 * allowing for TCP state, receive window, congestion window and MSS
 * Also retrieves the current send sequence number */
static inline int
exa_tcp_max_pkt_len(struct exa_tcp_conn * restrict ctx,
                    uint32_t * restrict seq, size_t * restrict len)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;
    uint32_t unacked_len, window_size, rwnd;

    if (state->state != EXA_TCP_ESTABLISHED &&
        state->state != EXA_TCP_CLOSE_WAIT)
    {
        /* Cannot send data in current state */
        return -1;
    }

    *seq = state->send_seq;

    unacked_len = state->send_seq - state->send_ack;
    rwnd = state->rwnd_end - state->send_ack;
    window_size = rwnd < state->cwnd ? rwnd : state->cwnd;

    if (window_size < unacked_len)
        *len = 0;
    else if (state->rmss < window_size - unacked_len)
        *len = state->rmss;
    else
        *len = window_size - unacked_len;

    return 0;
}

static inline void
exa_tcp_insert(int fd)
{
    exa_hashtable_ucast_insert(&__exa_tcp_sockfds, fd);
}

static inline void
exa_tcp_remove(int fd)
{
    exa_hashtable_ucast_remove(&__exa_tcp_sockfds, fd);
}

static inline int
exa_tcp_lookup(struct exa_endpoint * restrict ep)
{
    return exa_hashtable_ucast_lookup(&__exa_tcp_sockfds, ep);
}

static inline void
exa_tcp_listen(struct exa_tcp_conn * restrict ctx)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;

    assert(state->state == EXA_TCP_CLOSED);

    state->state = EXA_TCP_LISTEN;
}

static inline bool
exa_tcp_listening(struct exa_tcp_conn * restrict ctx)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;

    return state->state == EXA_TCP_LISTEN;
}

/* Generate initial sequence number for a new connection */
static inline uint32_t
exa_tcp_init_seq(void)
{
    struct timespec tv;
    uint32_t seq;

    /* Use the current time as the initial sequence number */
    clock_gettime(CLOCK_MONOTONIC_COARSE, &tv);
    seq = tv.tv_sec * 1000000000ULL + tv.tv_nsec;

    /* TODO: Randomise the sequence number in a secure way */

    return seq;
}

static inline void
exa_tcp_connect(struct exa_tcp_conn * restrict ctx,
                struct exa_endpoint_port * restrict port,
                uint64_t addr_csum)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;

    assert(state->state == EXA_TCP_CLOSED);

    /* Prepare cached header and pseudo header checksum */
    ctx->hdr.th_sport = port->local;
    ctx->hdr.th_dport = port->peer;
    ctx->hdr.th_seq = 0;
    ctx->hdr.th_ack = 0;
    ctx->hdr.th_off = sizeof(struct tcphdr) / 4;
    ctx->hdr.th_flags = 0;
    ctx->hdr.th_win = 0;
    ctx->hdr.th_sum = 0;

    ctx->ph_csum = csum(NULL, 0, addr_csum + htons(IPPROTO_TCP));

    /* Generate initial sequence number */
    state->send_ack = state->send_seq = exa_tcp_init_seq();
    state->rwnd_end = state->send_ack;

    /* Initialize stats */
    state->stats.init_send_seq = state->send_seq;

    state->state = EXA_TCP_SYN_SENT;
}

static inline void
exa_tcp_accept(struct exa_tcp_conn * restrict ctx,
               struct exa_endpoint_port * restrict port, uint64_t addr_csum,
               struct exa_tcp_init_state * restrict tcp_state)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;

    assert(state->state == EXA_TCP_CLOSED);

    /* Prepare cached header and pseudo header checksum */
    ctx->hdr.th_sport = port->local;
    ctx->hdr.th_dport = port->peer;
    ctx->hdr.th_seq = 0;
    ctx->hdr.th_ack = 0;
    ctx->hdr.th_off = sizeof(struct tcphdr) / 4;
    ctx->hdr.th_flags = 0;
    ctx->hdr.th_win = 0;
    ctx->hdr.th_sum = 0;

    ctx->ph_csum = csum(NULL, 0, addr_csum + htons(IPPROTO_TCP));

    state->send_ack = state->send_seq = tcp_state->local_seq;
    state->rwnd_end = state->send_ack + tcp_state->peer_window;
    state->rmss = tcp_state->peer_mss;
    state->wscale = tcp_state->peer_wscale;

    state->read_seq = state->recv_seq = tcp_state->peer_seq;

    /* Initialize stats */
    state->stats.init_send_seq = state->send_seq;
    state->stats.init_recv_seq = state->recv_seq;

    state->state = EXA_TCP_ESTABLISHED;
}

static inline void
exa_tcp_shutdown_write(struct exa_tcp_conn * restrict ctx)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;

    switch (state->state)
    {
    case EXA_TCP_SYN_SENT:
        state->state = EXA_TCP_CLOSED;
        break;
    case EXA_TCP_SYN_RCVD:
        state->state = EXA_TCP_FIN_WAIT_1;
        break;
    case EXA_TCP_ESTABLISHED:
        state->state = EXA_TCP_FIN_WAIT_1;
        break;
    case EXA_TCP_CLOSE_WAIT:
        state->state = EXA_TCP_LAST_ACK;
        break;
    default:
        /* Do nothing, write is already closed */
        break;
    }
}

/* Close the connection immediately after sending a reset packet */
static inline void
exa_tcp_reset(struct exa_tcp_conn * restrict ctx)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;

    state->state = EXA_TCP_CLOSED;
}

/* Return true if a connection is not yet established */
static inline bool
exa_tcp_connecting(struct exa_tcp_conn * restrict ctx)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;

    return state->state == EXA_TCP_SYN_SENT ||
           state->state == EXA_TCP_SYN_RCVD;
}

/* Return true if the write side of the connection has closed */
static inline bool
exa_tcp_write_closed(struct exa_tcp_conn * restrict ctx)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;

    return state->state != EXA_TCP_ESTABLISHED &&
           state->state != EXA_TCP_CLOSE_WAIT &&
           state->state != EXA_TCP_SYN_SENT &&
           state->state != EXA_TCP_SYN_RCVD &&
           state->state != EXA_TCP_LISTEN;
}

/* Return true if we need to send an ACK */
static inline bool
exa_tcp_ack_pending(struct exa_tcp_conn * restrict ctx)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;

    return state->ack_pending;
}

/* Update state after an ACK is sent */
static inline void
exa_tcp_clear_ack_pending(struct exa_tcp_conn * restrict ctx)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;

    state->ack_pending = false;
}

/* Calculate the value of the window field in the TCP header */
static inline uint16_t
__exa_tcp_calc_window(struct exa_socket_state * restrict state)
{
    struct exa_tcp_state * restrict tcp = &state->p.tcp;
    uint32_t rx_space;

    /* Calculate window size from remaining space in buffer */
    rx_space = state->rx_buffer_size - (tcp->recv_seq - tcp->read_seq);

    /* Window scaling is enabled if remote host gave a non-zero window scale */
    if (tcp->wscale != 0)
        rx_space >>= EXA_TCP_WSCALE;

    return rx_space < TCP_MAXWIN ? rx_space : TCP_MAXWIN;
}

/* Construct a packet with no data for the current state */
static inline bool
exa_tcp_build_ctrl(struct exa_tcp_conn * restrict ctx, char ** restrict hdr,
                   size_t * restrict hdr_len)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;
    struct tcphdr * restrict h;
    size_t optlen = 0;

    if (state->state == EXA_TCP_SYN_SENT || state->state == EXA_TCP_SYN_RCVD)
    {
        uint8_t *opts = (uint8_t *)(*hdr - 8);

        /* Add MSS and window scale options to header */
        opts[0] = TCPOPT_MAXSEG;
        opts[1] = TCPOLEN_MAXSEG;
        opts[2] = EXA_TCP_MSS >> 8;
        opts[3] = EXA_TCP_MSS & 0xFF;
        opts[4] = TCPOPT_NOP;
        opts[5] = TCPOPT_WINDOW;
        opts[6] = TCPOLEN_WINDOW;
        opts[7] = EXA_TCP_WSCALE;

        *hdr -= 8;
        *hdr_len += 8;
        optlen = 8;
    }

    h = (struct tcphdr *)(*hdr - sizeof(struct tcphdr));
    *h = ctx->hdr;

    switch (state->state)
    {
    case EXA_TCP_SYN_SENT:
        /* Send SYN */
        h->th_seq = htonl(state->send_seq - 1);
        h->th_ack = 0;
        h->th_flags = TH_SYN;
        break;

    case EXA_TCP_SYN_RCVD:
        /* Send SYN ACK */
        h->th_seq = htonl(state->send_seq - 1);
        h->th_ack = htonl(state->recv_seq);
        h->th_flags = TH_SYN | TH_ACK;
        break;

    case EXA_TCP_ESTABLISHED:
        /* Send ACK */
        h->th_seq = htonl(state->send_seq);
        h->th_ack = htonl(state->recv_seq);
        h->th_flags = TH_ACK;
        break;

    case EXA_TCP_CLOSE_WAIT:
        /* Send ACK for remote FIN */
        h->th_seq = htonl(state->send_seq);
        h->th_ack = htonl(state->recv_seq + 1);
        h->th_flags = TH_ACK;

    case EXA_TCP_FIN_WAIT_1:
        /* Send FIN */
        h->th_seq = htonl(state->send_seq);
        h->th_ack = htonl(state->recv_seq);
        h->th_flags = TH_FIN | TH_ACK;
        break;

    case EXA_TCP_FIN_WAIT_2:
        /* Send ACK */
        h->th_seq = htonl(state->send_seq);
        h->th_ack = htonl(state->recv_seq);
        h->th_flags = TH_ACK;
        break;

    case EXA_TCP_CLOSING:
        /* Send ACK for remote FIN */
        h->th_seq = htonl(state->send_seq);
        h->th_ack = htonl(state->recv_seq + 1);
        h->th_flags = TH_ACK;
        break;

    case EXA_TCP_LAST_ACK:
        /* Send FIN */
        h->th_seq = htonl(state->send_seq);
        h->th_ack = htonl(state->recv_seq + 1);
        h->th_flags = TH_FIN | TH_ACK;
        break;

    case EXA_TCP_TIME_WAIT:
        /* Send ACK for remote FIN */
        h->th_seq = htonl(state->send_seq + 1);
        h->th_ack = htonl(state->recv_seq + 1);
        h->th_flags = TH_ACK;
        break;

    default:
        /* Don't send a packet */
        return false;
    }

    h->th_win = htons(__exa_tcp_calc_window(ctx->state));
    h->th_off = (sizeof(struct tcphdr) + optlen) / 4;
    h->th_sum = ~csum(h, sizeof(struct tcphdr) + optlen,
                      ctx->ph_csum + htons(sizeof(struct tcphdr) + optlen));

    *hdr -= sizeof(struct tcphdr);
    *hdr_len += sizeof(struct tcphdr);

    return true;
}

/* Construct a RST packet for the current state */
static inline bool
exa_tcp_build_rst(struct exa_tcp_conn * restrict ctx, char ** restrict hdr,
                  size_t * restrict hdr_len)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;
    struct tcphdr * restrict h;

    h = (struct tcphdr *)(*hdr - sizeof(struct tcphdr));
    *h = ctx->hdr;

    switch (state->state)
    {
    case EXA_TCP_SYN_RCVD:
    case EXA_TCP_ESTABLISHED:
        h->th_seq = htonl(state->send_seq);
        h->th_ack = htonl(state->recv_seq);
        break;

    case EXA_TCP_CLOSE_WAIT:
        h->th_seq = htonl(state->send_seq);
        h->th_ack = htonl(state->recv_seq + 1);
        break;

    case EXA_TCP_FIN_WAIT_1:
    case EXA_TCP_FIN_WAIT_2:
        h->th_seq = htonl(state->send_seq + 1);
        h->th_ack = htonl(state->recv_seq);
        break;

    case EXA_TCP_CLOSING:
    case EXA_TCP_LAST_ACK:
    case EXA_TCP_TIME_WAIT:
        h->th_seq = htonl(state->send_seq + 1);
        h->th_ack = htonl(state->recv_seq + 1);
        break;

    default:
        /* Don't send a RST packet in these states */
        return false;
    }

    h->th_flags = TH_RST | TH_ACK;
    h->th_sum = ~csum(h, sizeof(struct tcphdr),
                      ctx->ph_csum + htons(sizeof(struct tcphdr)));

    *hdr -= sizeof(struct tcphdr);
    *hdr_len += sizeof(struct tcphdr);

    return true;
}

/* Construct a packet with data, only works when TCP is synchronised */
static inline void
exa_tcp_build_hdr(struct exa_tcp_conn * restrict ctx, char ** restrict hdr,
                  size_t * restrict hdr_len, size_t send_seq,
                  const struct iovec * restrict iov, size_t iovcnt,
                  size_t skip_len, size_t data_len)
{
    struct tcphdr * restrict h = (struct tcphdr *)(*hdr - sizeof(struct tcphdr));
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;
    uint64_t csum_hdr;

    assert(state->state == EXA_TCP_ESTABLISHED ||
           state->state == EXA_TCP_CLOSE_WAIT ||
           state->state == EXA_TCP_FIN_WAIT_1 ||
           state->state == EXA_TCP_CLOSING ||
           state->state == EXA_TCP_LAST_ACK);

    *h = ctx->hdr;

    h->th_seq = htonl(send_seq);
    h->th_ack = htonl(state->recv_seq +
                      (state->state == EXA_TCP_CLOSE_WAIT ? 1 : 0));
    h->th_flags = TH_PUSH | TH_ACK;

    h->th_win = htons(__exa_tcp_calc_window(ctx->state));

    csum_hdr = csum_part(h, sizeof(struct tcphdr), ctx->ph_csum +
                         htons(sizeof(struct tcphdr) + data_len));
    h->th_sum = ~csum_iov(iov, iovcnt, skip_len, data_len, csum_hdr);

    *hdr -= sizeof(struct tcphdr);
    *hdr_len += sizeof(struct tcphdr);
}

static inline int
exa_tcp_parse_hdr(char *hdr, char *read_end, size_t pkt_len, uint64_t addr_csum,
                  struct exa_endpoint_port * restrict port,
                  uint8_t ** restrict tcpopt, size_t * restrict tcpopt_len,
                  char ** restrict data_begin, uint32_t * restrict data_seq,
                  size_t * restrict data_len, uint32_t * restrict ack_seq,
                  uint8_t * restrict flags, uint16_t * restrict win,
                  uint64_t * restrict csum)
{
    const struct tcphdr * restrict h = (struct tcphdr *)hdr;

    if ((read_end - hdr) < sizeof(struct tcphdr))
        return -1;

    if (pkt_len < sizeof(struct tcphdr))
        return -1;

    /* Calculate checksum of pseudo-header and header */
    *csum = csum_part(hdr, h->th_off * 4,
                      addr_csum + htons(IPPROTO_TCP) + htons(pkt_len));

    /* Beginning of data in header chunk */
    *data_begin = hdr + (h->th_off * 4);

    /* TCP segment info */
    *data_len = pkt_len - (h->th_off * 4);
    *data_seq = ntohl(h->th_seq) + ((h->th_flags & TH_SYN) ? 1 : 0);

    /* Other header info */
    *ack_seq = ntohl(h->th_ack);
    *flags = h->th_flags;
    *win = ntohs(h->th_win);

    /* TCP options region */
    *tcpopt_len = (h->th_off * 4) - sizeof(struct tcphdr);
    *tcpopt = (uint8_t *)(hdr + sizeof(struct tcphdr));

    port->peer = h->th_sport;
    port->local = h->th_dport;

    return 0;
}

static inline int
exa_tcp_validate_csum(char *hdr, char *hdr_end, uint64_t * restrict csum)
{
    const struct tcphdr * restrict h = (struct tcphdr *)hdr;

    assert(hdr_end - hdr >= sizeof(struct tcphdr));

    /* Check checksum */
    if (h->th_sum != 0 && csum_pack(*csum) != 0xFFFF)
        return -1;

    return 0;
}

/* Apply options found in a SYN packet */
static inline void
exa_tcp_apply_syn_opts(struct exa_tcp_conn * restrict ctx,
                       uint8_t * restrict tcpopt, size_t tcpopt_len)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;
    size_t i;

    for (i = 0; i < tcpopt_len && tcpopt[i] != TCPOPT_EOL;
         i += (tcpopt[i] == TCPOPT_NOP) ? 1 : tcpopt[i + 1])
    {
        switch (tcpopt[i])
        {
        case TCPOPT_MAXSEG:
            state->rmss = ((uint16_t)tcpopt[i + 2] << 8) | tcpopt[i + 3];
            break;
        case TCPOPT_WINDOW:
            state->wscale = tcpopt[i + 2];
            break;
        }
    }
}

/* Drop packets which are not valid for the current state
 * Also do additional processing for SYN packets
 * This is called before the packet is validated */
static inline int
exa_tcp_pre_update_state(struct exa_tcp_conn * restrict ctx, uint8_t flags,
                         uint32_t data_seq, uint32_t ack_seq, size_t len,
                         uint8_t * restrict tcpopt, size_t tcpopt_len)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;

    if (state->state == EXA_TCP_LISTEN)
    {
        /* Packets for listening sockets are processed elsewhere */
        return -1;
    }

    if (flags & TH_RST)
    {
        if (state->state == EXA_TCP_SYN_SENT)
        {
            /* Drop RST packets with incorrect ACK */
            if (!(flags & TH_ACK) || ack_seq != state->send_seq)
                return -1;
            /* Reset sequence numbers so that the RST is accepted */
            state->read_seq = state->recv_seq = data_seq;
        }
    }
    else if (flags & TH_SYN)
    {
        if (state->state == EXA_TCP_SYN_SENT)
        {
            /* Reset sequence numbers */
            state->read_seq = state->recv_seq = data_seq;
            state->stats.init_recv_seq = state->recv_seq;

            /* Parse and apply TCP options */
            exa_tcp_apply_syn_opts(ctx, tcpopt, tcpopt_len);
        }
        else
        {
            /* SYN not allowed in current state */
            return -1;
        }
    }
    else
    {
        if (state->state == EXA_TCP_SYN_SENT)
        {
            /* SYN expected in current state */
            return -1;
        }
    }

    return 0;
}

static inline void
exa_tcp_update_state(struct exa_tcp_conn * restrict ctx, uint8_t flags,
                     uint32_t data_seq, uint32_t ack_seq, uint16_t win,
                     size_t len)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;

    if (flags & TH_ACK)
    {
        uint32_t send_ack = state->send_ack;
        uint32_t win_end = ack_seq + (win << state->wscale);
        uint32_t rwnd_end = state->rwnd_end;

        /* Check if got ACK for more of our sent data */
        while (seq_compare(send_ack, ack_seq) < 0)
            send_ack = __sync_val_compare_and_swap(&state->send_ack, send_ack,
                                                   ack_seq);

        /* Check if got new space in receiver buffer */
        while (seq_compare(rwnd_end, win_end) < 0)
            rwnd_end = __sync_val_compare_and_swap(&state->rwnd_end, rwnd_end,
                                                   win_end);
    }

    if ((flags & TH_RST) && seq_compare(data_seq, state->recv_seq) <= 0)
    {
        /* Connection reset, move to CLOSED state */
        if (state->state == EXA_TCP_SYN_SENT)
            ctx->state->error = ECONNREFUSED;
        else
            ctx->state->error = ECONNRESET;

        state->state = EXA_TCP_CLOSED;

        /* TODO: Flush send and receive buffers */

        return;
    }

    if (data_seq != state->recv_seq)
        state->ack_pending = true;

    switch (state->state)
    {
    case EXA_TCP_SYN_SENT:
        if ((flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK) &&
            seq_compare(state->send_seq, state->send_ack) <= 0)
        {
            /* Got SYN ACK */
            state->state = EXA_TCP_ESTABLISHED;
            state->ack_pending = true;
        }
        else if ((flags & (TH_SYN | TH_ACK)) == TH_SYN)
        {
            /* Simultaneous open */
            state->state = EXA_TCP_SYN_RCVD;
            state->ack_pending = true;
        }

        break;

    case EXA_TCP_SYN_RCVD:
        if ((flags & TH_ACK) &&
            seq_compare(state->send_seq, state->send_ack) <= 0)
        {
            /* Connection established */
            state->state = EXA_TCP_ESTABLISHED;
        }
        break;

    case EXA_TCP_ESTABLISHED:
        if ((flags & TH_FIN) &&
            seq_compare(data_seq + len, state->recv_seq) <= 0)
        {
            /* Remote peer has closed the connection */
            state->state = EXA_TCP_CLOSE_WAIT;
            state->ack_pending = true;
        }
        break;

    case EXA_TCP_FIN_WAIT_1:
        if ((flags & TH_FIN) &&
            seq_compare(data_seq + len, state->recv_seq) <= 0)
        {
            /* Simultaneous close */
            state->state = EXA_TCP_CLOSING;
            state->ack_pending = true;
        }
        else if ((flags & TH_ACK) &&
                 seq_compare(state->send_seq, state->send_ack) < 0)
        {
            /* Received ACK for our FIN, but remote peer is not closed */
            state->state = EXA_TCP_FIN_WAIT_2;
        }
        break;

    case EXA_TCP_FIN_WAIT_2:
        if ((flags & TH_FIN) &&
            seq_compare(data_seq + len, state->recv_seq) <= 0)
        {
            /* Remote peer has closed the connection */
            state->state = EXA_TCP_TIME_WAIT;
            state->ack_pending = true;
        }
        break;

    case EXA_TCP_CLOSING:
        if ((flags & TH_ACK) &&
            seq_compare(state->send_seq, state->send_ack) < 0)
        {
            state->state = EXA_TCP_TIME_WAIT;
        }
        break;

    case EXA_TCP_LAST_ACK:
        if ((flags & TH_ACK) &&
            seq_compare(state->send_seq, state->send_ack) < 0)
        {
            state->state = EXA_TCP_CLOSED;
        }
        break;
    }
}

#endif /* EXASOCK_TCP_H */
