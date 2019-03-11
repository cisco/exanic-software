#ifndef EXASOCK_TCP_BUFFER_H
#define EXASOCK_TCP_BUFFER_H

#include "kernel/consts.h"

static inline int
seq_compare(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b);
}

static inline bool
proc_seq_update(uint32_t *proc_seq, uint32_t *old_seq, uint32_t new_seq)
{
    uint32_t prev;

    do
    {
        prev = __sync_val_compare_and_swap(proc_seq, *old_seq, new_seq);
        if (prev == *old_seq)
            return true;
        *old_seq = prev;
    } while (seq_compare(new_seq, *old_seq) > 0);

    return false;
}

static inline void
out_of_order_reset(struct exa_tcp_state * restrict tcp)
{
    tcp->out_of_order.seg_count = 0;
    tcp->out_of_order.ack_seq = tcp->recv_seq;
    tcp->dup_acks_seq = tcp->out_of_order.ack_seq - 1;
}

static inline void
out_of_order_seg_count(struct exa_tcp_state * restrict tcp, uint32_t recv_seq)
{
    if (tcp->out_of_order.ack_seq == recv_seq)
    {
        tcp->out_of_order.seg_count++;
        if (tcp->out_of_order.seg_count == EXA_TCP_FAST_RETRANS_THRESH)
            tcp->dup_acks_seq = tcp->out_of_order.ack_seq;
    }
    else
    {
        tcp->out_of_order.ack_seq = recv_seq;
        tcp->out_of_order.seg_count = 1;
    }
}

static inline int
exa_tcp_rx_buffer_alloc(struct exa_socket * restrict sock, uint32_t seg_seq,
                        size_t seg_len, uint32_t * restrict proc_seq,
                        char ** restrict buf1, size_t * restrict buf1_len,
                        char ** restrict buf2, size_t * restrict buf2_len,
                        size_t * restrict skip_len)
{
    struct exa_socket_state * restrict state = sock->state;
    struct exa_tcp_state * restrict tcp = &state->p.tcp;
    uint32_t rx_buffer_mask = state->rx_buffer_size - 1;
    uint32_t read_seq = tcp->read_seq;
    uint32_t seg_end_seq = seg_seq + seg_len;
    uint32_t wrap_seq = seg_end_seq & ~rx_buffer_mask;
    uint32_t alloc_seq;

    /* Check for space in the ring buffer */
    if (seg_end_seq - read_seq > state->rx_buffer_size)
        return -1;

    *proc_seq = tcp->proc_seq;

    /* Check if packet gives us any new data */
    if (seq_compare(seg_end_seq, *proc_seq) <= 0)
        return -1;

    /* Lock the new data for processing */
    if (!proc_seq_update(&tcp->proc_seq, proc_seq, seg_end_seq))
        return -1;

    if (seq_compare(seg_seq, *proc_seq) < 0)
    {
        /* Packet overlaps with already processed data region */
        *skip_len = *proc_seq - seg_seq;
        alloc_seq = *proc_seq;
    }
    else
    {
        /* Packet does not overlap with already processed data region */
        *skip_len = 0;
        alloc_seq = seg_seq;
    }

    if (seq_compare(alloc_seq, wrap_seq) < 0)
    {
        /* Region is wrapped */
        *buf1 = sock->rx_buffer + (alloc_seq & rx_buffer_mask);
        *buf1_len = wrap_seq - alloc_seq;
        *buf2 = sock->rx_buffer;
        *buf2_len = seg_end_seq - wrap_seq;
    }
    else
    {
        /* Region is not wrapped */
        *buf1 = sock->rx_buffer + (alloc_seq & rx_buffer_mask);
        *buf1_len = seg_end_seq - alloc_seq;
        *buf2 = NULL;
        *buf2_len = 0;
    }

    return 0;
}

/* This function is safe to call with a bogus sequence number if len == 0 */
static inline void
exa_tcp_rx_buffer_commit(struct exa_socket * restrict sock,
                         uint32_t seq, size_t len, uint32_t prev_proc_seq)
{
    struct exa_socket_state * restrict state = sock->state;
    struct exa_tcp_state * restrict tcp = &state->p.tcp;
    uint32_t recv_seq = tcp->recv_seq;
    uint32_t proc_seq;
    unsigned int i, j, k;

    if (len == 0)
    {
        /* Just handle an out of order segment and return */
        if (seq_compare(recv_seq, seq) < 0)
            out_of_order_seg_count(tcp, recv_seq);
        else if (seq_compare(recv_seq, tcp->out_of_order.ack_seq) > 0)
            out_of_order_reset(tcp);

        return;
    }

    /* Remove out of order segments already processed by kernel */
    if (tcp->recv_seg[0].end - tcp->recv_seg[0].begin != 0 &&
        seq_compare(tcp->recv_seg[0].end, recv_seq) <= 0)
    {
        for (i = 1; i < EXA_TCP_MAX_RX_SEGMENTS &&
             tcp->recv_seg[i].end - tcp->recv_seg[i].begin != 0 &&
             seq_compare(tcp->recv_seg[i].end, recv_seq) <= 0; i++)
            ;
        for (j = 0; i < EXA_TCP_MAX_RX_SEGMENTS; i++, j++)
            tcp->recv_seg[j] = tcp->recv_seg[i];
        for (; j < EXA_TCP_MAX_RX_SEGMENTS; j++)
            tcp->recv_seg[j].begin = tcp->recv_seg[j].end = 0;
        if (tcp->recv_seg[0].end - tcp->recv_seg[0].begin != 0 &&
            seq_compare(tcp->recv_seg[0].begin, recv_seq) < 0)
            tcp->recv_seg[0].begin = recv_seq;
    }

    if (recv_seq == seq)
    {
        /* Extend acked region */

        proc_seq = tcp->proc_seq;
        if (tcp->recv_seg[0].end - tcp->recv_seg[0].begin != 0 &&
            seq_compare(tcp->recv_seg[0].begin, proc_seq) <= 0)
        {
            /* Merge in segments from out of order segment list */
            for (i = 1; i < EXA_TCP_MAX_RX_SEGMENTS &&
                 tcp->recv_seg[i].end - tcp->recv_seg[i].begin > 0 &&
                 seq_compare(tcp->recv_seg[i].begin, proc_seq) <= 0; i++)
                ;
            if (seq_compare(proc_seq, tcp->recv_seg[i - 1].end) < 0)
            {
                /* We have locked segment for processing and gained control over
                 * proc_seq pointer, so we can update it safely now. */
                tcp->proc_seq = tcp->recv_seg[i - 1].end;
            }

            /* Move remaining segments */
            for (j = 0; i < EXA_TCP_MAX_RX_SEGMENTS; i++, j++)
                tcp->recv_seg[j] = tcp->recv_seg[i];
            for (; j < EXA_TCP_MAX_RX_SEGMENTS; j++)
                tcp->recv_seg[j].begin = tcp->recv_seg[j].end = 0;
        }

        /* Assert that the next segment cannot be merged in */
        assert(tcp->recv_seg[0].end - tcp->recv_seg[0].begin == 0 ||
                seq_compare(tcp->recv_seg[0].begin, tcp->proc_seq) > 0);

        /* We are certain that kernel is not in the middle of processing of any
         * new data right now (recv_seq == seq). We can safely update recv_seq.
         */
        tcp->recv_seq = tcp->proc_seq;

        out_of_order_reset(tcp);
    }
    else
    {
        /* Update out of order segments counter */
        out_of_order_seg_count(tcp, recv_seq);

        /* Find place to insert into out of order segment list */
        for (i = 0; i < EXA_TCP_MAX_RX_SEGMENTS &&
             tcp->recv_seg[i].end - tcp->recv_seg[i].begin != 0 &&
             seq_compare(tcp->recv_seg[i].end, seq) < 0; i++)
            ;

        if (i >= EXA_TCP_MAX_RX_SEGMENTS)
        {
            /* Too many out of order segments, we will drop this one */
        }
        else if (tcp->recv_seg[i].end - tcp->recv_seg[i].begin == 0)
        {
            /* Insert as new segment at end of list */
            tcp->recv_seg[i].begin = seq;
            tcp->recv_seg[i].end = seq + len;
        }
        else if (seq_compare(seq + len, tcp->recv_seg[i].begin) < 0)
        {
            /* Insert as separate segment
             * If there are too many segments, last segment is discarded */
            for (j = EXA_TCP_MAX_RX_SEGMENTS - 1; j > i; j--)
                tcp->recv_seg[j] = tcp->recv_seg[j - 1];
            tcp->recv_seg[i].begin = seq;
            tcp->recv_seg[i].end = seq + len;
        }
        else
        {
            /* Assert that the new data can be merged into current segment */
            assert(seq_compare(seq, tcp->recv_seg[i].end) <= 0);
            assert(seq_compare(tcp->recv_seg[i].begin, seq + len) <= 0);

            /* Expand current segment */
            if (seq_compare(seq, tcp->recv_seg[i].begin) < 0)
                tcp->recv_seg[i].begin = seq;
            if (seq_compare(tcp->recv_seg[i].end, seq + len) < 0)
                tcp->recv_seg[i].end = seq + len;

            /* Merge segments into current segment */
            for (j = i + 1; j < EXA_TCP_MAX_RX_SEGMENTS &&
                 tcp->recv_seg[j].end - tcp->recv_seg[j].begin != 0 &&
                 seq_compare(tcp->recv_seg[j].begin,
                             tcp->recv_seg[i].end) <= 0; j++)
                ;
            if (seq_compare(tcp->recv_seg[i].end, tcp->recv_seg[j - 1].end) < 0)
                tcp->recv_seg[i].end = tcp->recv_seg[j - 1].end;

            /* Move remaining segments */
            for (k = i + 1; j < EXA_TCP_MAX_RX_SEGMENTS; j++, k++)
                tcp->recv_seg[k] = tcp->recv_seg[j];
            for (; k < EXA_TCP_MAX_RX_SEGMENTS; k++)
                tcp->recv_seg[k].begin = tcp->recv_seg[k].end = 0;
        }

        if (tcp->recv_seg[0].begin == recv_seq &&
            tcp->recv_seg[0].end - tcp->recv_seg[0].begin != 0 &&
            recv_seq == prev_proc_seq)
        {
            /* Kernel has progressed in the meantime and the first out of order
             * segment is now ready for reading. We can update recv_seq safely,
             * since we have checked that kernel is not in the middle of
             * processing of any new data right now (recv_seq == prev_proc_seq).
             */
            tcp->recv_seq = tcp->proc_seq = tcp->recv_seg[0].end;

            /* Move remaining segments */
            for (i = 1; i < EXA_TCP_MAX_RX_SEGMENTS; i++)
                tcp->recv_seg[i - 1] = tcp->recv_seg[i];
            tcp->recv_seg[i - 1].begin = tcp->recv_seg[i - 1].end = 0;
        }
        else
        {
            /* The segment has just been inserted into out of order segment list.
             * Reset segment processing pointer back from where we took it. */
            tcp->proc_seq = prev_proc_seq;
        }
    }
}

static inline void
exa_tcp_rx_buffer_abort(struct exa_socket * restrict sock,
                        uint32_t seq, size_t len, uint32_t prev_proc_seq)
{
    struct exa_socket_state * restrict state = sock->state;
    struct exa_tcp_state * restrict tcp = &state->p.tcp;
    unsigned int i, j;

    /* Make sure invalid region is not in out of order segment list */
    for (i = 0, j = 0; i < EXA_TCP_MAX_RX_SEGMENTS &&
         tcp->recv_seg[i].end - tcp->recv_seg[i].begin != 0; i++, j++)
    {
        if (seq_compare(seq, tcp->recv_seg[i].end) < 0 &&
            seq_compare(tcp->recv_seg[i].begin, seq + len) < 0)
        {
            /* Out of order segment overlaps with invalidated region
             * Remove the segment completely and let TCP recover the data */
            i++;
        }

        if (j < i)
        {
            if (i < EXA_TCP_MAX_RX_SEGMENTS)
                tcp->recv_seg[j] = tcp->recv_seg[i];
            else
                tcp->recv_seg[j].begin = tcp->recv_seg[j].end = 0;
        }
    }

    /* Reset segment processing pointer back from where we took it */
    if (len > 0)
        tcp->proc_seq = prev_proc_seq;
}

static inline int
exa_tcp_rx_buffer_read_begin(struct exa_socket * restrict sock,
                             char ** restrict buf1, size_t * restrict len1,
                             char ** restrict buf2, size_t * restrict len2)
{
    struct exa_socket_state * restrict state = sock->state;
    struct exa_tcp_state * restrict tcp = &state->p.tcp;
    uint32_t rx_buffer_mask = state->rx_buffer_size - 1;
    uint32_t read_seq = tcp->read_seq;
    uint32_t recv_seq = tcp->recv_seq;
    uint32_t buf_offset = tcp->read_seq & rx_buffer_mask;

    /* Return all available data in buffer up to wrap boundary */
    if (recv_seq - read_seq <= state->rx_buffer_size - buf_offset)
    {
        *buf1 = sock->rx_buffer + buf_offset;
        *len1 = recv_seq - read_seq;
        *buf2 = NULL;
        *len2 = 0;
    }
    else
    {
        *buf1 = sock->rx_buffer + buf_offset;
        *len1 = state->rx_buffer_size - buf_offset;
        *buf2 = sock->rx_buffer;
        *len2 = (recv_seq - read_seq) - *len1;
    }

    return 0;
}

static inline void
exa_tcp_rx_buffer_read_end(struct exa_socket * restrict sock, size_t len)
{
    struct exa_socket_state * restrict state = sock->state;
    struct exa_tcp_state * restrict tcp = &state->p.tcp;

    tcp->read_seq += len;

    if (len > 0)
    {
        /* Window update is needed */
        tcp->ack_pending = true;
    }
}

static inline int
exa_tcp_rx_buffer_read_conn(struct exa_socket * restrict sock,
                            struct exa_endpoint * restrict ep,
                            struct exa_tcp_init_state * restrict tcp_state)
{
    struct exa_socket_state * restrict state = sock->state;
    struct exa_tcp_state *tcp = &state->p.tcp;
    uint32_t next_write = tcp->recv_seq;
    uint32_t next_read = tcp->read_seq;
    struct exa_tcp_new_connection *conn;
    size_t offs;

    if (next_write == next_read)
    {
        /* No entries available */
        return -1;
    }

    offs = next_read & (state->rx_buffer_size - 1);
    conn = (struct exa_tcp_new_connection *)(sock->rx_buffer + offs);

    ep->addr.local = conn->local_addr;
    ep->addr.peer = conn->peer_addr;
    ep->port.local = conn->local_port;
    ep->port.peer = conn->peer_port;

    tcp_state->local_seq = conn->local_seq;
    tcp_state->peer_seq = conn->peer_seq;
    tcp_state->peer_window = conn->peer_window;
    tcp_state->peer_mss = conn->peer_mss;
    tcp_state->peer_wscale = conn->peer_wscale;

    tcp->read_seq = next_read + sizeof(struct exa_tcp_new_connection);

    return 0;
}

static inline bool
exa_tcp_rx_buffer_eof(struct exa_socket * restrict sock)
{
    struct exa_socket_state * restrict state = sock->state;
    struct exa_tcp_state * restrict tcp = &state->p.tcp;

    return tcp->read_seq == tcp->recv_seq &&
           (tcp->state == EXA_TCP_CLOSE_WAIT || tcp->state == EXA_TCP_CLOSING ||
            tcp->state == EXA_TCP_LAST_ACK || tcp->state == EXA_TCP_TIME_WAIT ||
            tcp->state == EXA_TCP_CLOSED);
}

static inline bool
exa_tcp_rx_buffer_ready(struct exa_socket * restrict sock)
{
    struct exa_socket_state * restrict state = sock->state;
    struct exa_tcp_state * restrict tcp = &state->p.tcp;

    return tcp->read_seq != tcp->recv_seq ||
           tcp->state == EXA_TCP_CLOSE_WAIT || tcp->state == EXA_TCP_CLOSING ||
           tcp->state == EXA_TCP_LAST_ACK || tcp->state == EXA_TCP_TIME_WAIT ||
           tcp->state == EXA_TCP_CLOSED;
}

static inline void
exa_tcp_tx_buffer_write(struct exa_socket * restrict sock,
                        const struct iovec * restrict iov, size_t iovcnt,
                        size_t skip_len, size_t send_len)
{
    struct exa_socket_state * restrict state = sock->state;
    struct exa_tcp_state * restrict tcp = &state->p.tcp;
    uint32_t send_seq = tcp->send_seq;
    uint32_t buf_offs;
    size_t i, offs;
    size_t iov_len = skip_len + send_len;

    assert(send_len <= state->tx_buffer_size);

    buf_offs = send_seq & (state->tx_buffer_size - 1);
    offs = 0;
    for (i = 0; i < iovcnt && offs < iov_len; i++)
    {
        size_t len = iov[i].iov_len < iov_len - offs ?
                     iov[i].iov_len : iov_len - offs;
        size_t skip = offs < skip_len ? skip_len - offs : 0;

        if (len <= skip)
        {
            offs += len;
        }
        else if (buf_offs + len - skip < state->tx_buffer_size)
        {
            memcpy(sock->tx_buffer + buf_offs, iov[i].iov_base + skip,
                   len - skip);
            offs += len;
            buf_offs += len - skip;
        }
        else
        {
            size_t l = state->tx_buffer_size - buf_offs;

            memcpy(sock->tx_buffer + buf_offs, iov[i].iov_base + skip, l);
            memcpy(sock->tx_buffer, iov[i].iov_base + skip + l, len - skip - l);
            offs += len;
            buf_offs = len - skip - l;
        }
    }

    tcp->adv_wnd_end = tcp->wnd_end_pending;
    tcp->send_seq = send_seq + send_len;
    tcp->tx_consistent = 1;
}

/* Get data from the tx buffer as an iovec */
static inline void
exa_tcp_tx_buffer_get(struct exa_socket * restrict sock, uint32_t seq,
                      size_t len, struct iovec * restrict iov,
                      size_t * restrict iovcnt)
{
    struct exa_socket_state * restrict state = sock->state;
    uint32_t tx_buffer_mask = (state->tx_buffer_size - 1);
    uint32_t seq_end = seq + len;

    if ((seq & ~tx_buffer_mask) == ((seq_end - 1) & ~tx_buffer_mask))
    {
        *iovcnt = 1;
        iov[0].iov_base = sock->tx_buffer + (seq & tx_buffer_mask);
        iov[0].iov_len = len;
    }
    else
    {
        *iovcnt = 2;
        iov[0].iov_base = sock->tx_buffer + (seq & tx_buffer_mask);
        iov[0].iov_len = state->tx_buffer_size - (seq & tx_buffer_mask);
        iov[1].iov_base = sock->tx_buffer;
        iov[1].iov_len = (seq_end & tx_buffer_mask);
    }
}

static inline bool
exa_tcp_tx_buffer_empty(struct exa_socket * restrict sock)
{
    struct exa_tcp_state * restrict tcp = &sock->state->p.tcp;

    return seq_compare(tcp->send_seq, tcp->send_ack) <= 0;
}

#endif /* EXASOCK_TCP_BUFFER_H */
