#ifndef EXASOCK_KERNEL_STRUCTS_H_3184709AEFC64CF680494E0D75134908
#define EXASOCK_KERNEL_STRUCTS_H_3184709AEFC64CF680494E0D75134908

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
    uint8_t state;
};

#define EXA_DST_ENTRY_EMPTY             0
#define EXA_DST_ENTRY_INCOMPLETE        1
#define EXA_DST_ENTRY_VALID             2
#define EXA_DST_ENTRY_INVALID           0xFF

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

#define EXA_TCP_MAX_RX_SEGMENTS         5

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
    /* Next unacknowledged sent sequence number */
    uint32_t send_ack;
    /* Receiver window */
    uint32_t rwnd;

    uint8_t __reserved0[4];

    /* Next received sequence number to be delivered to user */
    uint32_t read_seq;
    /* Next receive sequence number expected on the network.
     * Data must be written to the rx_buffer before recv_seq is incremented. */
    uint32_t recv_seq;

    /* Out of order received segments */
    struct {
        uint32_t begin;
        uint32_t end;
    } recv_seg[EXA_TCP_MAX_RX_SEGMENTS];

    /* 64 */
    /* user read-mostly, kernel read-mostly */

    /* Receiver maximum segment size */
    uint16_t rmss;
    /* Remote window scale */
    uint8_t wscale;
    /* TCP connection state */
    uint8_t state;
    /* Slow start after idle? */
    uint8_t ss_after_idle;

    uint8_t __reserved1[59];

    /* 128 */
    /* user read-mostly, kernel read-write */

    /* Congestion window */
    uint32_t cwnd;
    /* Slow start threshold */
    uint32_t ssthresh;

    /* Backup TCP state fields updated in kernel in case a packet gets received
     * which has not been processed by the library yet */
    struct
    {
        /* Next unacknowledged sent sequence number */
        uint32_t send_ack;
        /* Receiver window */
        uint32_t rwnd;
    } kernel;

    uint8_t __reserved2[52];

    /* 192 */
    /* user write-mostly, kernel read-write */

    /* Set to true to signal that an ACK is needed */
    uint8_t ack_pending;

    uint8_t __reserved4[63];

    /* 320 */
    /* Stats related info: user initialize, kernel read-write */

    struct {
        uint32_t init_send_seq;
        uint32_t init_recv_seq;

        uint32_t prev_send_seq;
        uint32_t prev_send_ack;
        uint32_t prev_recv_seq;
        uint32_t prev_read_seq;

        uint8_t __reserved[40];
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

#endif /* EXASOCK_KERNEL_STRUCTS_H_3184709AEFC64CF680494E0D75134908 */
