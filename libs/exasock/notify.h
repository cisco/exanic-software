#ifndef EXASOCK_NOTIFY_H
#define EXASOCK_NOTIFY_H

#define EXA_NOTIFY_MAX_QUEUE 32

/* Event flags */
#define EXA_NOTIFY_IN   0x00000001
#define EXA_NOTIFY_OUT  0x00000004
#define EXA_NOTIFY_ERR  0x00000008
#define EXA_NOTIFY_HUP  0x00000010
#define EXA_NOTIFY_ET   0x80000000

struct exa_notify_kern_epoll
{
    uint32_t lock;

    /* File descriptor of this epoll if exasock kernel instance exists */
    int fd;

    /* Number of exasock file descriptors added to this exasock kernel instance
     * of epoll */
    int ref_cnt;

    /* State of epoll shared between kernel and user */
    struct exasock_epoll_state *state;
};

struct exa_notify_fd
{
    /* True iff file descriptor is in this exa_notify set */
    bool present;

    /* True iff file descriptor is in the maybe-ready queue */
    bool enqueued;

    /* True if there an event possibly pending
     * Set to false when an edge-triggered event is delivered */
    bool event_pending;

    /* Events must be updated using accessor functions */
    uint32_t events;

    /* User data */
    uint64_t data;

    /* File descriptor number for next and prev elements */
    int list_next;
    int list_prev;
};

struct exa_notify_fd_cnt
{
    uint32_t lock;

    /* Number of bypass file descriptors belonging to this epoll */
    unsigned int bypass;

    /* Number of native file descriptors belonging to this epoll */
    unsigned int native;
};

struct exa_notify
{
    struct exa_notify_fd *fd_table;

    /* Linked list of file descriptors belonging to this epoll */
    int list_head;

    /* The maybe-ready queue */
    /* FIXME: Can we make this lock-free? */
    int queue_len;
    int queue[EXA_NOTIFY_MAX_QUEUE];
    uint32_t queue_lock;

    /* File descriptor counters */
    struct exa_notify_fd_cnt fd_cnt;

    /* State of exasock kernel instance of epoll */
    struct exa_notify_kern_epoll ep;
};

int exa_notify_kern_epoll_add(struct exa_notify * restrict no,
                              struct exa_socket * restrict sock);
struct exa_notify *exa_notify_alloc(void);
void exa_notify_free(struct exa_notify * restrict no);
int exa_notify_insert_sock(struct exa_notify * restrict no,
                           struct exa_socket * restrict sock,
                           uint32_t events);
int exa_notify_modify_sock(struct exa_notify * restrict no,
                           struct exa_socket * restrict sock,
                           uint32_t events);
int exa_notify_remove_sock(struct exa_notify * restrict no,
                           struct exa_socket * restrict sock);
void exa_notify_remove_sock_all(struct exa_socket * restrict sock);
void exa_notify_udp_init(struct exa_socket * restrict sock);
void exa_notify_tcp_init(struct exa_socket * restrict sock);

static inline bool
exa_notify_has_sock(struct exa_notify * restrict no,
                    struct exa_socket * restrict sock)
{
    return sock->notify_parent == no;
}

static inline void
exa_notify_enable_sock_bypass(struct exa_socket * restrict sock)
{
    struct exa_notify * restrict no = sock->notify_parent;

    if (no != NULL)
    {
        exa_lock(&no->fd_cnt.lock);
        no->fd_cnt.bypass++;
        no->fd_cnt.native--;
        exa_unlock(&no->fd_cnt.lock);
    }
}

/* Add a socket to the maybe-ready queue */
static inline void
exa_notify_queue_insert(struct exa_notify * restrict no, int fd)
{
    assert(fd >= 0 && fd < exa_socket_table_size);

    exa_lock(&no->queue_lock);

    if (!no->fd_table[fd].enqueued)
    {
        if (no->queue_len >= 0)
        {
            if (no->queue_len < EXA_NOTIFY_MAX_QUEUE)
            {
                no->queue[no->queue_len] = fd;
                no->queue_len++;
            }
            else
            {
                /* Overflowed maybe-ready queue */
                no->queue_len = -1;
            }
        }

        no->fd_table[fd].enqueued = true;
    }

    exa_unlock(&no->queue_lock);
}

/* Get the maybe-ready queue
 * Returns length of queue, or -1 if queue was in overflow state
 *
 * The caller needs call either exa_notify_queue_reinsert() or
 * exa_notify_queue_clear for each fd that was in the queue */
static inline int
exa_notify_queue_get(struct exa_notify * restrict no,
                     int queue[EXA_NOTIFY_MAX_QUEUE])
{
    int len;

    assert(no->queue_lock);

    len = no->queue_len;
    if (len > 0)
        memcpy(queue, no->queue, sizeof(int) * len);
    no->queue_len = 0;

    return len;
}

static inline void
exa_notify_queue_reinsert(struct exa_notify * restrict no, int fd)
{
    assert(fd >= 0 && fd < exa_socket_table_size);
    assert(no->fd_table[fd].enqueued);
    assert(no->queue_lock);

    if (no->queue_len >= 0)
    {
        if (no->queue_len < EXA_NOTIFY_MAX_QUEUE)
        {
            no->queue[no->queue_len] = fd;
            no->queue_len++;
        }
        else
        {
            /* Overflowed maybe-ready queue */
            no->queue_len = -1;
        }
    }
}

static inline void
exa_notify_queue_clear(struct exa_notify * restrict no, int fd)
{
    assert(fd >= 0 && fd < exa_socket_table_size);

    no->fd_table[fd].enqueued = false;
}

/* Remove a socket from the maybe-ready queue if it is there */
static inline void
exa_notify_queue_remove(struct exa_notify * restrict no, int fd)
{
    int i;

    exa_lock(&no->queue_lock);

    for (i = 0; i < no->queue_len; i++)
    {
        if (no->queue[i] == fd)
        {
            no->queue_len--;
            memcpy(&no->queue[i], &no->queue[i + 1],
                   (no->queue_len - i) * sizeof(int));
            break;
        }
    }

    exa_unlock(&no->queue_lock);
}

/* Called once when socket is ready for reading */
static inline void
exa_notify_read_edge(struct exa_notify * restrict no,
                     struct exa_socket * restrict sock)
{
    int fd = exa_socket_fd(sock);

    assert(fd >= 0 && fd < exa_socket_table_size);

    if (no->fd_table[fd].events & EXA_NOTIFY_IN)
    {
        no->fd_table[fd].event_pending = true;
        exa_notify_queue_insert(no, fd);
    }
}

static inline void
exa_notify_read_edge_all(struct exa_socket * restrict sock)
{
    if (sock->notify_parent != NULL)
        exa_notify_read_edge(sock->notify_parent, sock);
}

/* Called once when socket is ready for writing */
static inline void
exa_notify_write_edge(struct exa_notify * restrict no,
                      struct exa_socket * restrict sock)
{
    int fd = exa_socket_fd(sock);

    assert(fd >= 0 && fd < exa_socket_table_size);

    if (no->fd_table[fd].events & EXA_NOTIFY_OUT)
    {
        no->fd_table[fd].event_pending = true;
        exa_notify_queue_insert(no, fd);
    }
}

static inline void
exa_notify_write_edge_all(struct exa_socket * restrict sock)
{
    if (sock->notify_parent != NULL)
        exa_notify_write_edge(sock->notify_parent, sock);
}

/* Called once when socket hangup occurs */
static inline void
exa_notify_hangup_edge(struct exa_notify * restrict no,
                       struct exa_socket * restrict sock)
{
    int fd = exa_socket_fd(sock);

    assert(fd >= 0 && fd < exa_socket_table_size);

    no->fd_table[fd].event_pending = true;
    exa_notify_queue_insert(no, fd);
}

static inline void
exa_notify_hangup_edge_all(struct exa_socket * restrict sock)
{
    if (sock->notify_parent != NULL)
        exa_notify_hangup_edge(sock->notify_parent, sock);
}

/* Called when an edge-triggered event has been delivered */
static inline void
exa_notify_clear(struct exa_notify * restrict no, int fd)
{
    assert(fd >= 0 && fd < exa_socket_table_size);

    no->fd_table[fd].event_pending = false;
}

/* Check TCP read ready state and update */
static inline void
exa_notify_tcp_read_update(struct exa_socket * restrict sock)
{
    bool old_rx_ready = sock->rx_ready;

    assert(sock->type == SOCK_STREAM);
    assert(sock->state->rx_lock);

    sock->rx_ready = exa_tcp_rx_buffer_ready(sock);

    if (!old_rx_ready && sock->rx_ready)
        exa_notify_read_edge_all(sock);
}

/* Check TCP write ready state and update */
static inline void
exa_notify_tcp_write_update(struct exa_socket * restrict sock)
{
    bool old_tx_ready = sock->tx_ready;

    assert(sock->type == SOCK_STREAM);
    /* tx_ready is updated on receive - this is why we test for rx_lock */
    assert(sock->state->rx_lock);

    sock->tx_ready = !exanic_tcp_connecting(sock);

    if (!old_tx_ready && sock->tx_ready)
        exa_notify_write_edge_all(sock);
}

/* This will cause a write ready edge on next activity on the TCP socket */
static inline void
exa_notify_tcp_write_fake_unready(struct exa_socket * restrict sock)
{
    assert(sock->type == SOCK_STREAM);

    sock->tx_ready = false;
}

/* Check for TCP connection hangup */
static inline void
exa_notify_tcp_hangup_update(struct exa_socket * restrict sock)
{
    bool old_eof_ready = sock->eof_ready;

    assert(sock->type == SOCK_STREAM);

    sock->eof_ready = exanic_tcp_write_closed(sock);

    if (!old_eof_ready && sock->eof_ready)
        exa_notify_hangup_edge_all(sock);
}

/* Check UDP read ready state and update */
static inline void
exa_notify_udp_read_update(struct exa_socket * restrict sock)
{
    bool old_rx_ready = sock->rx_ready;

    assert(sock->type == SOCK_DGRAM);
    assert(sock->state->rx_lock);

    sock->rx_ready = exa_udp_queue_ready(sock);

    if (!old_rx_ready && sock->rx_ready)
        exa_notify_read_edge_all(sock);
}

/* Update TCP ready state */
static inline void
exa_notify_tcp_update(struct exa_socket * restrict sock)
{
    assert(sock->type == SOCK_STREAM);
    assert(sock->state->rx_lock);

    exa_notify_tcp_read_update(sock);
    exa_notify_tcp_write_update(sock);
    exa_notify_tcp_hangup_update(sock);
}

/* Update ready state according to the socket type */
static inline void
exa_notify_update(struct exa_socket * restrict sock)
{
    assert(sock->state->rx_lock);

    if (sock->domain == AF_INET && sock->type == SOCK_DGRAM)
        exa_notify_udp_read_update(sock);
    else if (sock->domain == AF_INET && sock->type == SOCK_STREAM)
        exa_notify_tcp_update(sock);
}

#endif /* EXASOCK_NOTIFY_H */
