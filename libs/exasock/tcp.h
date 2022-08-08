#ifndef EXASOCK_TCP_H
#define EXASOCK_TCP_H

#define EXA_TCP_SS_AFTER_IDLE_DEF       0
#define EXA_TCP_KEEPALIVE_INTVL_DEF     75
#define EXA_TCP_KEEPALIVE_PROBES_DEF    9
#define EXA_TCP_KEEPALIVE_TIME_DEF      7200

#ifdef TCP_LISTEN_SOCKET_PROFILING

#define PROFILE_INFO_INIT_TCP_SEQ(tcp, tcp_state) \
    do \
    { \
        tcp->profile.init_local_seq = tcp_state->local_seq - 1; \
        tcp->profile.init_peer_seq =  tcp_state->peer_seq - 1; \
    } while(0);

#define PROFILE_INFO_TCP_TX_RX_EVENT(rx, ctx, state, f, a, seq_n, ack_n) \
    do \
    { \
        struct tcp_packet_event p; \
        p.flags = (f << 0) | (a << 4); \
        p.ack = ack_n; \
        p.seq = seq_n; \
        register_tcp_event(true, rx, ctx, state, &p, __LINE__, __FILE__); \
    } while(0);

#define PROFILE_INFO_TCP_SHUTDOWN_EVENT(ctx, state) \
        register_tcp_event(false, false, ctx, state, NULL, __LINE__, __FILE__);

#else /* ifdef TCP_LISTEN_SOCKET_PROFILING */

#define PROFILE_INFO_TCP_TX_RX_EVENT(rx, ctx, state, f, a, seq_n, ack_n)
#define PROFILE_INFO_TCP_SHUTDOWN_EVENT(ctx, state)
#define PROFILE_INFO_INIT_TCP_SEQ(tcp, tcp_state)
#endif /* ifdef TCP_LISTEN_SOCKET_PROFILING */

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

#ifdef TCP_LISTEN_SOCKET_PROFILING
static inline void register_tcp_event(bool packet, bool rx, struct exa_tcp_conn * restrict ctx,
                                          int current_state, struct tcp_packet_event* pkt_evt,
                                          uint32_t lineno, const char* fname)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;
    struct tcp_state_event* ev_ptr;
    struct tcp_packet_event* pkt_event_ptr;

    /* this function may take up to a couple of milliseconds
     * to acquire the rx_lock if server undergoes connection flooding */
    exa_lock(&ctx->state->rx_lock);

    if (state->profile.event_index == 10)
    {
        state->profile.overflow = 1;
        goto unlock;
    }
    ev_ptr = &state->profile.st_history[state->profile.event_index++];
    memset(ev_ptr, 0, sizeof(*ev_ptr));
    pkt_event_ptr = &ev_ptr->pkt_event;
    ev_ptr->kernel = false;

    ev_ptr->state = current_state;
    ev_ptr->line = lineno;

    strncpy(ev_ptr->fname, fname, sizeof(ev_ptr->fname) - 1);
    ev_ptr->fname[sizeof(ev_ptr->fname) - 1] = '\0';

    clock_gettime(CLOCK_REALTIME, (struct timespec*)&ev_ptr->ts);

    if (packet)
    {
        if (rx)
            ev_ptr->rx = 1;
        else
            ev_ptr->tx = 1;
        pkt_event_ptr->flags = pkt_evt->flags;
        pkt_event_ptr->ack = pkt_evt->ack;
        pkt_event_ptr->seq = pkt_evt->seq;
    }
    else
        ev_ptr->shutdown = 1;
unlock:

    exa_unlock(&ctx->state->rx_lock);
}
#endif /* ifdef TCP_LISTEN_SOCKET_PROFILING */

/* Calculate the size of the largest segment that can be sent right now,
 * allowing for TCP state, receive window, congestion window and MSS.
 * In case of ATE offloaded connections the most recently updated ATE window
 * limit is used. Also retrieves the current send sequence number. */
static inline int
exa_tcp_max_seg_len(struct exa_tcp_conn * restrict ctx, bool is_ate,
                    uint32_t * restrict seq, size_t * restrict len)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;
    uint32_t wnd_end;
    int32_t wnd_space;

    if (state->state != EXA_TCP_ESTABLISHED &&
        state->state != EXA_TCP_CLOSE_WAIT)
    {
        /* Cannot send data in current state */
        return -1;
    }

    *seq = state->send_seq;

    if (!is_ate)
    {
        uint32_t cwnd_end = state->send_ack + state->cwnd;
        uint32_t rwnd_end = state->rwnd_end;
        wnd_end = seq_compare(cwnd_end, rwnd_end) < 0 ? cwnd_end : rwnd_end;
    }
    else
    {
        wnd_end = ntohl(state->ate_wnd_end);
    }

    wnd_space = wnd_end - *seq;

    if (wnd_space < 0)
        *len = 0;
    else if (state->rmss < wnd_space)
        *len = state->rmss;
    else
        *len = (size_t)wnd_space;

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
exa_tcp_listen(struct exa_tcp_conn * restrict ctx, int backlog)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;

    assert(state->state == EXA_TCP_CLOSED);

    state->state = EXA_TCP_LISTEN;
    state->backlog = (backlog > (ctx->state->rx_buffer_size / sizeof(struct exa_tcp_new_connection))) ? EXA_SOMAXCONN : backlog;
}

static inline bool
exa_tcp_listening(struct exa_tcp_conn * restrict ctx)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;

    return state->state == EXA_TCP_LISTEN;
}

/* Generate initial sequence number for a new connection */
int exa_sys_get_isn(int fd, uint32_t *isn);

static inline int
exa_tcp_init_seq(int fd, uint32_t *isn)
{
    return exa_sys_get_isn(fd, isn);
}

static inline int
exa_tcp_state_init_conn(int fd, struct exa_socket_state * restrict state)
{
    struct exa_tcp_state * restrict tcp = &state->p.tcp;
    uint32_t isn = 0;
    int ret = 0;
    if ((ret = exa_tcp_init_seq(fd, &isn)))
        return ret;

    /* Generate initial sequence number */
    tcp->send_ack = tcp->send_seq = isn;
    tcp->rwnd_end = tcp->send_ack;

    /* Initialize stats */
    tcp->stats.init_send_seq = tcp->send_seq;
    return 0;
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

    state->state = EXA_TCP_SYN_SENT;
}

static inline void
exa_tcp_state_init_acc(struct exa_socket_state * restrict state,
                       struct exa_tcp_init_state * restrict tcp_state)
{
    struct exa_tcp_state * restrict tcp = &state->p.tcp;

    tcp->send_ack = tcp->send_seq = tcp_state->local_seq;
    tcp->rwnd_end = tcp->send_ack + tcp_state->peer_window;
    tcp->rmss = tcp_state->peer_mss;
    tcp->wscale = tcp_state->peer_wscale;

    PROFILE_INFO_INIT_TCP_SEQ(tcp, tcp_state);
    tcp->read_seq = tcp->recv_seq = tcp->proc_seq = tcp_state->peer_seq;
    tcp->adv_wnd_end = tcp->recv_seq + EXA_TCP_SYNACK_WIN;
    tcp->out_of_order.ack_seq = tcp->recv_seq;
    tcp->dup_acks_seq = tcp->out_of_order.ack_seq - 1;

    /* Initialize stats */
    tcp->stats.init_send_seq = tcp->send_seq;
    tcp->stats.init_recv_seq = tcp->recv_seq;
}

static inline void
exa_tcp_accept(struct exa_tcp_conn * restrict ctx,
               struct exa_endpoint_port * restrict port, uint64_t addr_csum)
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

    state->state = EXA_TCP_ESTABLISHED;
}

static inline void
exa_tcp_shutdown_write(struct exa_tcp_conn * restrict ctx)
{
    volatile struct exa_tcp_state *state = &ctx->state->p.tcp;

update_state:
    switch (state->state)
    {
    case EXA_TCP_SYN_SENT:
        state->state = EXA_TCP_CLOSED;
        break;
    case EXA_TCP_SYN_RCVD:
        state->state = EXA_TCP_FIN_WAIT_1;
        break;
    case EXA_TCP_ESTABLISHED:
        if (!__sync_bool_compare_and_swap(&state->state,
                                          EXA_TCP_ESTABLISHED,
                                          EXA_TCP_FIN_WAIT_1))
            goto update_state;
        PROFILE_INFO_TCP_SHUTDOWN_EVENT(ctx,EXA_TCP_FIN_WAIT_1);
        break;
    case EXA_TCP_CLOSE_WAIT:
        if (!__sync_bool_compare_and_swap(&state->state,
                                          EXA_TCP_CLOSE_WAIT,
                                          EXA_TCP_LAST_ACK))
            goto update_state;
        PROFILE_INFO_TCP_SHUTDOWN_EVENT(ctx, EXA_TCP_LAST_ACK);
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

/* Update state after an ACK is sent */
static inline void
exa_tcp_clear_ack_pending(struct exa_tcp_conn * restrict ctx)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;

    if(state->state != EXA_TCP_FIN_WAIT_1)
        state->ack_pending = false;
}

/* Calculate the value of the window field in the TCP header */
static inline uint16_t
__exa_tcp_calc_window(struct exa_socket_state * restrict state,
                      struct exa_tcp_state * restrict tcp, uint32_t recv_seq)
{
    uint32_t rx_space;

    /* Calculate window size from remaining space in buffer */
    rx_space = state->rx_buffer_size - (recv_seq - tcp->read_seq);

    /* Window scaling is enabled if remote host gave a non-zero window scale */
    if (tcp->wscale != 0)
        rx_space >>= EXA_TCP_WSCALE;

    return rx_space < TCP_MAXWIN ? rx_space : TCP_MAXWIN;
}

/* Get the value of the window field for the TCP header and keep it
 * in the internal state */
static inline uint16_t
exa_tcp_get_window(struct exa_socket_state * restrict state, uint32_t recv_seq)
{
    struct exa_tcp_state * restrict tcp = &state->p.tcp;
    uint16_t window = __exa_tcp_calc_window(state, tcp, recv_seq);

    /* Store the window end point that is going to be advertised now */
    tcp->wnd_end_pending = recv_seq +
                           (window << (tcp->wscale ? EXA_TCP_WSCALE : 0));
    return window;
}

/* Construct a packet with no data for the current state.
 * Record the window endpoint that will be advertised if this packet is sent.
 * Note that it is safe to call this function without actually sending
 * the packet. */
static inline bool
exa_tcp_build_ctrl(struct exa_tcp_conn * restrict ctx, char ** restrict hdr,
                   size_t * restrict hdr_len)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;
    struct tcphdr * restrict h;
    uint32_t recv_seq = state->recv_seq;
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
        h->th_ack = htonl(recv_seq);
        h->th_flags = TH_SYN | TH_ACK;
        break;

    case EXA_TCP_ESTABLISHED:
        /* Send ACK */
        h->th_seq = htonl(state->send_seq);
        h->th_ack = htonl(recv_seq);
        h->th_flags = TH_ACK;
        PROFILE_INFO_TCP_TX_RX_EVENT(false, ctx, EXA_TCP_ESTABLISHED, 0, 1, state->send_seq, recv_seq);
        break;

    case EXA_TCP_CLOSE_WAIT:
        /* Send ACK for remote FIN */
        h->th_seq = htonl(state->send_seq);
        h->th_ack = htonl(recv_seq + 1);
        h->th_flags = TH_ACK;
        PROFILE_INFO_TCP_TX_RX_EVENT(false, ctx, EXA_TCP_CLOSE_WAIT, 0, 1, state->send_seq, recv_seq + 1);
        break;

    case EXA_TCP_FIN_WAIT_1:
        /* Send FIN */
        h->th_seq = htonl(state->send_seq);
        h->th_ack = htonl(recv_seq);
        h->th_flags = TH_FIN | TH_ACK;
        PROFILE_INFO_TCP_TX_RX_EVENT(false, ctx, EXA_TCP_FIN_WAIT_1, 1, 1, state->send_seq, recv_seq);
        break;

    case EXA_TCP_FIN_WAIT_2:
        /* Send ACK */
        h->th_seq = htonl(state->send_seq);
        h->th_ack = htonl(recv_seq);
        h->th_flags = TH_ACK;
        PROFILE_INFO_TCP_TX_RX_EVENT(false, ctx, EXA_TCP_FIN_WAIT_2, 0, 1, state->send_seq, recv_seq);
        break;

    case EXA_TCP_CLOSING:
        /* Send ACK for remote FIN */
        h->th_seq = htonl(state->send_seq + 1);
        h->th_ack = htonl(recv_seq + 1);
        h->th_flags = TH_ACK;
        PROFILE_INFO_TCP_TX_RX_EVENT(false, ctx, EXA_TCP_CLOSING, 0, 1, (state->send_seq + 1), (recv_seq + 1));
        break;

    case EXA_TCP_LAST_ACK:
        /* Send FIN */
        h->th_seq = htonl(state->send_seq);
        h->th_ack = htonl(recv_seq + 1);
        h->th_flags = TH_FIN | TH_ACK;
        PROFILE_INFO_TCP_TX_RX_EVENT(false, ctx, EXA_TCP_LAST_ACK, 1, 1, state->send_seq, (recv_seq + 1));
        break;

    case EXA_TCP_TIME_WAIT:
        /* Send ACK for remote FIN */
        h->th_seq = htonl(state->send_seq + 1);
        h->th_ack = htonl(recv_seq + 1);
        h->th_flags = TH_ACK;
        PROFILE_INFO_TCP_TX_RX_EVENT(false, ctx, EXA_TCP_TIME_WAIT, 0, 1, state->send_seq + 1, (recv_seq + 1));
        break;

    default:
        /* Don't send a packet */
        return false;
    }

    /* Calculate the window field and keep it in the internal state */
    h->th_win = htons(exa_tcp_get_window(ctx->state, recv_seq));

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

/* Construct a packet with data, only works when TCP is synchronised.
 * Record the window endpoint that will be advertised if this packet is sent.
 * Note that it is safe to call this function without actually sending
 * the packet. */
static inline void
exa_tcp_build_hdr(struct exa_tcp_conn * restrict ctx, char ** restrict hdr,
                  size_t * restrict hdr_len, size_t send_seq,
                  const struct iovec * restrict iov, size_t iovcnt,
                  size_t skip_len, size_t data_len)
{
    struct tcphdr * restrict h = (struct tcphdr *)(*hdr - sizeof(struct tcphdr));
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;
    uint32_t recv_seq = state->recv_seq;
    uint64_t csum_hdr;

    assert(state->state == EXA_TCP_ESTABLISHED ||
           state->state == EXA_TCP_CLOSE_WAIT ||
           state->state == EXA_TCP_FIN_WAIT_1 ||
           state->state == EXA_TCP_CLOSING ||
           state->state == EXA_TCP_LAST_ACK);

    *h = ctx->hdr;

    h->th_seq = htonl(send_seq);
    h->th_ack = htonl(recv_seq + (state->state == EXA_TCP_CLOSE_WAIT ? 1 : 0));
    h->th_flags = TH_PUSH | TH_ACK;
    /* Calculate the window field and keep it in the internal state */
    h->th_win = htons(exa_tcp_get_window(ctx->state, recv_seq));

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
    size_t hdr_len = h->th_off * 4;

    if ((read_end - hdr) < sizeof(struct tcphdr))
        return -1;

    if (hdr_len < sizeof(struct tcphdr))
        return -1;

    if (pkt_len < hdr_len)
        return -1;

    /* Calculate checksum of pseudo-header and header */
    *csum = csum_part(hdr, hdr_len,
                      addr_csum + htons(IPPROTO_TCP) + htons(pkt_len));

    /* Beginning of data in header chunk */
    *data_begin = hdr + hdr_len;

    /* TCP segment info */
    *data_len = pkt_len - hdr_len;
    *data_seq = ntohl(h->th_seq) + ((h->th_flags & TH_SYN) ? 1 : 0);

    /* Other header info */
    *ack_seq = ntohl(h->th_ack);
    *flags = h->th_flags;
    *win = ntohs(h->th_win);

    /* TCP options region */
    *tcpopt_len = hdr_len - sizeof(struct tcphdr);
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
            if (state->rmss > EXA_TCP_MSS)
                state->rmss = EXA_TCP_MSS;
            break;
        case TCPOPT_WINDOW:
            state->wscale = tcpopt[i + 2];
            break;
        }
    }
}

static inline void
exa_tcp_error_close(struct exa_tcp_conn * restrict ctx, int error)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;
    ctx->state->error = error;
    state->state = EXA_TCP_CLOSED;
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

    if (flags & TH_RST)
    {
        if (state->state == EXA_TCP_SYN_SENT)
        {
            /* Drop RST packets with incorrect ACK */
            if (!(flags & TH_ACK) || ack_seq != state->send_seq)
                return -1;
            /* Reset sequence numbers so that the RST is accepted */
            state->read_seq = state->recv_seq = state->proc_seq = data_seq;
        }
    }
    else if (flags & TH_SYN)
    {
        if (state->state == EXA_TCP_SYN_SENT)
        {
            /* Reset sequence numbers */
            state->read_seq = state->recv_seq = state->proc_seq = data_seq;
            state->adv_wnd_end = state->recv_seq;
            state->out_of_order.ack_seq = state->recv_seq;
            state->dup_acks_seq = state->out_of_order.ack_seq - 1;
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
                     uint32_t data_seq, uint32_t ack_seq, uint16_t win)
{
    struct exa_tcp_state * restrict state = &ctx->state->p.tcp;

    if (flags & TH_ACK)
    {
        uint32_t send_ack = state->send_ack;
        uint32_t win_end = ack_seq +
                           (win << ((flags & TH_SYN) ? 0 : state->wscale));
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

    /* FIXME: When we do graceful shutdown instead of closing with RST,
     *        the condition for processing RST should be updated.
     *        A reset is valid if its sequence number is in the window. */
    if ((flags & TH_RST) && seq_compare(data_seq, state->recv_seq) <= 0)
    {
        int err;
        /* Connection reset, move to CLOSED state */
        if (state->state == EXA_TCP_SYN_SENT)
            err = ECONNREFUSED;
        else
            err = ECONNRESET;

        exa_tcp_error_close(ctx, err);

        /* TODO: Flush send and receive buffers */

        return;
    }

    if (seq_compare(data_seq, state->recv_seq) < 0)
        state->ack_pending = true;
}

/* Returns true if a new connection has just been established */
static inline bool
exa_tcp_update_conn_state(struct exa_tcp_conn * restrict ctx, uint8_t flags,
                          uint32_t data_seq, size_t len)
{
    volatile struct exa_tcp_state *state = &ctx->state->p.tcp;
    bool fw1_fin = false, fw1_ack = false;
    bool new_conn = false;

update_state:
    switch (state->state)
    {
    case EXA_TCP_SYN_SENT:
        if ((flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK) &&
            seq_compare(state->send_seq, state->send_ack) <= 0)
        {
            /* Got SYN ACK */
            state->state = EXA_TCP_ESTABLISHED;
            state->ack_pending = true;
            new_conn = true;
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
            new_conn = true;
        }
        break;

    case EXA_TCP_ESTABLISHED:
        if ((flags & TH_FIN) &&
            seq_compare(data_seq + len, state->recv_seq) <= 0)
        {
            /* Remote peer has closed the connection */
            if (!__sync_bool_compare_and_swap(&state->state,
                                              EXA_TCP_ESTABLISHED,
                                              EXA_TCP_CLOSE_WAIT))
                goto update_state;
            state->ack_pending = true;
            PROFILE_INFO_TCP_TX_RX_EVENT(true, ctx, EXA_TCP_CLOSE_WAIT, !!(flags & TH_FIN), !!(flags & TH_ACK), data_seq, state->send_ack);
        }
        break;

    case EXA_TCP_FIN_WAIT_1:

        fw1_fin = ((flags & TH_FIN) &&
                  seq_compare(data_seq + len, state->recv_seq) <= 0);
        fw1_ack = ((flags & TH_ACK) &&
                  seq_compare(state->send_seq, state->send_ack) < 0);

        if (fw1_fin && fw1_ack)
        {
            /* Received ACK for our FIN, remote peer is also closed */
            if (!__sync_bool_compare_and_swap(&state->state,
                                              EXA_TCP_FIN_WAIT_1,
                                              EXA_TCP_TIME_WAIT))
                goto update_state;
            state->ack_pending = true;
            PROFILE_INFO_TCP_TX_RX_EVENT(true, ctx, EXA_TCP_TIME_WAIT, !!(flags & TH_FIN), !!(flags & TH_ACK), data_seq, state->send_ack);
        }
        else if (fw1_fin)
        {
            /* Simultaneous close */
            if (!__sync_bool_compare_and_swap(&state->state,
                                              EXA_TCP_FIN_WAIT_1,
                                              EXA_TCP_CLOSING))
                goto update_state;
            state->ack_pending = true;
            PROFILE_INFO_TCP_TX_RX_EVENT(true, ctx, EXA_TCP_CLOSING, !!(flags & TH_FIN), !!(flags & TH_ACK), data_seq, state->send_ack);
        }
        else if (fw1_ack)
        {
            /* Received ACK for our FIN, but remote peer is not closed */
            if (!__sync_bool_compare_and_swap(&state->state,
                                              EXA_TCP_FIN_WAIT_1,
                                              EXA_TCP_FIN_WAIT_2))
                goto update_state;
            PROFILE_INFO_TCP_TX_RX_EVENT(true, ctx, EXA_TCP_FIN_WAIT_2, !!(flags & TH_FIN), !!(flags & TH_ACK), data_seq, state->send_ack);
        }
        break;

    case EXA_TCP_FIN_WAIT_2:
        if ((flags & TH_FIN) &&
            seq_compare(data_seq + len, state->recv_seq) <= 0)
        {
            /* Remote peer has closed the connection */
            if (!__sync_bool_compare_and_swap(&state->state,
                                              EXA_TCP_FIN_WAIT_2,
                                              EXA_TCP_TIME_WAIT))
                goto update_state;
            state->ack_pending = true;
            PROFILE_INFO_TCP_TX_RX_EVENT(true, ctx, EXA_TCP_TIME_WAIT, !!(flags & TH_FIN), !!(flags & TH_ACK), data_seq, state->send_ack);
        }
        break;

    case EXA_TCP_CLOSING:
        if ((flags & TH_ACK) &&
            seq_compare(state->send_seq, state->send_ack) < 0)
        {
            if (!__sync_bool_compare_and_swap(&state->state,
                                              EXA_TCP_CLOSING,
                                              EXA_TCP_TIME_WAIT))
                goto update_state;
            PROFILE_INFO_TCP_TX_RX_EVENT(true, ctx, EXA_TCP_TIME_WAIT, !!(flags & TH_FIN), !!(flags & TH_ACK), data_seq, state->send_ack);
        }
        break;

    case EXA_TCP_CLOSE_WAIT:
        if ((flags & TH_FIN) &&
            seq_compare(data_seq + len, state->recv_seq) <= 0)
        {
            state->ack_pending = true;
        }
        break;

    case EXA_TCP_LAST_ACK:
        if ((flags & TH_ACK) &&
            seq_compare(state->send_seq, state->send_ack) < 0)
        {
            if (!__sync_bool_compare_and_swap(&state->state,
                                              EXA_TCP_LAST_ACK,
                                              EXA_TCP_CLOSED))
                goto update_state;
            PROFILE_INFO_TCP_TX_RX_EVENT(true, ctx, EXA_TCP_LAST_ACK, !!(flags & TH_FIN), !!(flags & TH_ACK), data_seq, state->send_ack);
        }
        break;
    }
    return new_conn;
}

#endif /* EXASOCK_TCP_H */
