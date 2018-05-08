#ifndef EXASOCK_KERNEL_STRUCTS_H
#define EXASOCK_KERNEL_STRUCTS_H

static inline uint32_t
exa_dst_hash(uint32_t a)
{
    /* Based on 32 bit integer hash by Thomas Wang.
     * http://burtleburtle.net/bob/hash/integer.html */
    a += ~(a << 15);
    a ^=  (a >> 10);
    a +=  (a << 3);
    a ^=  (a >> 6);
    a += ~(a << 11);
    a ^=  (a >> 16);
    return a;
}

struct exa_dst_entry
{
    uint32_t dst_addr;
    uint32_t src_addr;
    uint8_t eth_addr[6];
    uint8_t gen_id;
    uint8_t def_rt:1;
    uint8_t state:7;
};

#define EXA_DST_ENTRY_EMPTY             0
#define EXA_DST_ENTRY_INCOMPLETE        1
#define EXA_DST_ENTRY_VALID             2
#define EXA_DST_ENTRY_INVALID           3

struct exa_udp_state
{
    uint32_t next_write;
    uint32_t next_read;
};

#define EXA_TCP_CLOSED                  0
#define EXA_TCP_LISTEN                  1
#define EXA_TCP_SYN_SENT                2
#define EXA_TCP_SYN_RCVD                3
#define EXA_TCP_ESTABLISHED             4
#define EXA_TCP_CLOSE_WAIT              5
#define EXA_TCP_FIN_WAIT_1              6
#define EXA_TCP_FIN_WAIT_2              7
#define EXA_TCP_CLOSING                 8
#define EXA_TCP_LAST_ACK                9
#define EXA_TCP_TIME_WAIT               10

#define EXA_TCP_MAX_RX_SEGMENTS         6

/*
 * Locking in TCP state structs
 *
 * No locking needed for:
 * - Reading region between send_ack and send_seq in tx_buffer
 *   (Must check send_ack after read)
 * - Reading region between read_seq and recv_seq in rx_buffer
 *   (Must check read_seq after read)
 *
 * tx_lock is needed for:
 * - Updating send_seq
 *
 * rx_lock is needed for:
 * - Updating read_seq, recv_seq and send_ack
 * - Reading or updating recv_seg
 */

struct exa_tcp_state
{
    /* user read-write, kernel read-mostly */

    /* Next send sequence number.
     * Data must be written to the tx_buffer before send_seq is incremented. */
    uint32_t send_seq;
    /* Next received sequence number to be delivered to user */
    uint32_t read_seq;
    /* First sequence number beyond the local receive window most recently
     * advertised by libexasock */
    uint32_t adv_wnd_end;
    /* Next receive sequence number expected on the network for which at least
     * three out of order segments have been noticed in libexasock. This is the
     * Acknowledgment Number to be sent from kernel in respective duplicate ACKs.
     * Valid only when equal to recv_seq. */
    uint32_t dup_acks_seq;

    uint8_t __reserved0[48];

    /* 64 */
    /* user read-write, kernel not interested */

    /* First sequence number beyond the local receive window most recently
     * pre-staged to be advertised by libexasock. This value is going to be
     * moved to adv_wnd_end as soon as a segment gets transmitted.
     * Note: Updating of this field does not affect duplicate ACKs generation
     *       until it gets moved to adv_wnd_end. It is safe then to update this
     *       field without actually sending the segment. */
    uint32_t wnd_end_pending;

    /* Out of order received segments */
    struct {
        uint32_t begin;
        uint32_t end;
    } recv_seg[EXA_TCP_MAX_RX_SEGMENTS];

    /* Out of order segments counter used for duplicate ACKs generation */
    struct {
        /* Acknowledgment Number to be sent in the duplicate ACK.
         * It is the next receive sequence number expected on the network at
         * the moment the out of order segment got received. */
        uint32_t ack_seq;
        /* Number of out of order segments processed for the same next receive
         * sequence number expected on the network. */
        uint8_t seg_count;
    } out_of_order;

    uint8_t __reserved1[7];

    /* 128 */
    /* either user read-write and kernel read-mostly, or
     * user read-mostly and kernel read-write.
     * Note: In most of scenarios the first case applies. The second
     *       case applies when kernel is ahead of the library with processing of
     *       received packets (might happen when application does not poll
     *       receive buffer for a while).
     */

    /* Next unacknowledged sent sequence number */
    uint32_t send_ack;
    /* First send sequence number beyond receiver window
     * (send_ack + Receiver Window Size) */
    uint32_t rwnd_end;
    /* Next receive sequence number expected on the network.
     * Data must be written to the socket's rx_buffer before recv_seq is
     * incremented. */
    uint32_t recv_seq;
    /* Next receive sequence number to be processed in ExaNIC buffer.
     * User or kernel stack increments proc_seq to lock a data segment for
     * processing. Data segment must be locked before it can be written to
     * the socket's rx_buffer. */
    uint32_t proc_seq;

    uint8_t __reserved2[48];

    /* 192 */
    /* user read-mostly, kernel read-mostly */

    /* Receiver maximum segment size */
    uint16_t rmss;
    /* Remote window scale */
    uint8_t wscale;
    /* TCP connection state */
    uint8_t state;
    /* Keep-alive settings */
    struct {
        uint32_t time;
        uint32_t intvl;
        uint32_t probes;
    } keepalive;
    /* Timeout permissible on sending a TCP segment, in milliseconds. This
     * is set using the "TCP_USER_TIMEOUT" socket option, at the option
     * level IPPROTO_TCP. Zero is treated as "unset".
     *
     * If a connection times out due to this option, any current or future
     * syscalls on this socket will fail, and errno will be set to ETIMEDOUT.
     *
     * It is checked and enforced in the TCP connection worker only when there
     * is outstanding (un-ACKed) data.
     */
    uint32_t user_timeout_ms;
    /* Slow start after idle? */
    uint8_t ss_after_idle;

    uint8_t __reserved3[43];

    /* 256 */
    /* user read-mostly, kernel read-write */

    /* Congestion window */
    uint32_t cwnd;
    /* Slow start threshold */
    uint32_t ssthresh;

    uint8_t __reserved4[56];

    /* 320 */
    /* user write-mostly, kernel read-write */

    /* Set to true to signal that an ACK is needed */
    uint8_t ack_pending;

    uint8_t __reserved5[63];

    /* 384 */
    /* Stats related info: user initialize, kernel read-write */

    struct {
        uint32_t init_send_seq;
        uint32_t init_recv_seq;

        uint8_t __reserved[56];
    } stats;
};

struct exa_socket_state
{
    /* Socket info, set by kernel driver */
    int16_t domain;
    int16_t type;
    int32_t rx_buffer_size;
    int32_t tx_buffer_size;

    /* Locks */
    uint32_t rx_lock;
    uint32_t tx_lock;

    /* Socket bind and connect state, set by kernel driver */
    union {
        struct {
            uint32_t local_addr;
            uint32_t peer_addr;
            uint16_t local_port;
            uint16_t peer_port;
        } ip;
    } e;

    /* 32 */

    /* Other socket state */
    uint16_t error;
    uint8_t rx_shutdown;
    uint8_t tx_shutdown;

    uint8_t __reserved0[28];

    /* 64 */

    /* Protocol state, used by libexasock */
    union {
        struct exa_udp_state udp;
        struct exa_tcp_state tcp;
    } p;
};

struct exa_udp_queue_hdr
{
    uint32_t len;
    uint32_t local_addr;
    uint32_t peer_addr;
    uint16_t local_port;
    uint16_t peer_port;
};

struct exa_udp_queue_ftr
{
    uint32_t sw_ts_sec;
    uint32_t sw_ts_nsec;
    uint32_t hw_ts_sec;
    uint32_t hw_ts_nsec;
};

/* Entry is created after a new connection moves to the ESTABLISHED state */
struct exa_tcp_new_connection
{
    uint32_t local_addr;
    uint32_t peer_addr;
    uint16_t local_port;
    uint16_t peer_port;

    /* First sequence number after SYN packet */
    uint32_t local_seq;
    uint32_t peer_seq;

    /* Initial window size provided by remote peer */
    uint16_t peer_window;

    /* The mss and wscale options as provided by remote peer */
    uint16_t peer_mss;
    uint16_t peer_wscale;

    /* Pad to power of 2 size */
    uint32_t __reserved[2];
};

#define EXASOCK_EPOLL_FD_READY_RING_SIZE 512    /* Must be a power of 2 */
#define EXASOCK_EPOLL_FD_READY_IDX_MASK \
                            (EXASOCK_EPOLL_FD_READY_RING_SIZE - 1)
#define EXASOCK_EPOLL_FD_READY_IDX_NEXT(idx) \
                            (((idx) + 1) & EXASOCK_EPOLL_FD_READY_IDX_MASK)
#define EXASOCK_EPOLL_FD_READY_IDX_INC(idx) \
                            ((idx) = EXASOCK_EPOLL_FD_READY_IDX_NEXT(idx))
#define EXASOCK_EPOLL_FD_READY_RING_FULL(n_rd, n_wr) \
                            (EXASOCK_EPOLL_FD_READY_IDX_NEXT(n_wr) == n_rd)

struct exasock_epoll_state
{
    /* Ring to notify user about listening sockets got ready for reading */
    int fd_ready[EXASOCK_EPOLL_FD_READY_RING_SIZE];

    /* Index of a next entry in fd_ready ring to be read by user.
     * This index is updated by user. */
    int next_read;

    /* Index of a next entry in fd_ready ring to be written by kernel.
     * This index is updated by kernel.  */
    int next_write;
};

#endif /* EXASOCK_KERNEL_STRUCTS_H */
