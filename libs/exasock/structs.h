#ifndef STRUCTS_H_562CD82818334BCAAEA0F7C939E7DDA3
#define STRUCTS_H_562CD82818334BCAAEA0F7C939E7DDA3

struct exa_endpoint_ipaddr
{
    in_addr_t local;
    in_addr_t peer;
};

struct exa_endpoint_port
{
    in_port_t local;
    in_port_t peer;
};

struct exa_endpoint
{
    struct exa_endpoint_ipaddr addr;
    struct exa_endpoint_port port;
};

struct exa_timestamp
{
    uint32_t sec;
    uint32_t nsec;
};

struct exa_timeo
{
    bool enabled;
    struct timeval val;
};

/* This struct is input for exa_tcp_accept() */
struct exa_tcp_init_state
{
    uint32_t local_seq;
    uint32_t peer_seq;
    uint16_t peer_window;
    uint16_t peer_mss;
    uint8_t peer_wscale;
};

#define MAX_NUM_EPOLL   4

/* NOTE: Update exa_socket_zero() if struct layout is changed! */
struct exa_socket
{
    /* Read lock - all operations that use the socket
     * Write lock - creating/destroying socket data structures */
    exa_rwlock_t lock;

    /* Incremented whenever a socket is cleared so that blocking functions
     * can detect that the socket has changed */
    int gen_id;

    /* These fields mirror the native socket settings */
    int domain;
    int type;
    int protocol;
    int flags;

    /* Bypass socket state */
    bool bypass;
    bool bound;
    bool connected;

    /* Disable entering bypass mode on this socket */
    bool disable_bypass;

    /* Bound to specific device with SO_BINDTODEVICE */
    bool bound_to_device;

    /* If listening on all interfaces, all_if is true and listen_if is NULL
     * Otherwise all_if is false and listen_if is not NULL */
    bool all_if;
    struct exanic_ip *listen_if;

    /* Protocol context structs */
    union {
        struct exanic_udp *udp;
        struct exanic_tcp *tcp;
    } ctx;

    /* Cannot change bound endpoint after insertion into hash table */
    union {
        struct exa_endpoint ip;
    } bind;

    /* For chaining hash table entries */
    int hashtable_next_fd;

    /* For chaining socket list entries */
    struct exa_socket *list_prev;
    struct exa_socket *list_next;

    /* Socket state shared by all copies of this fd */
    struct exa_socket_state *state;

    /* Protocol specific buffers shared by all copies of this fd */
    char *rx_buffer;
    char *tx_buffer;

    /* Local copy of the socket ready state, used for edge detection */
    bool rx_ready;
    bool tx_ready;
    bool eof_ready;

    /* Socket is of a type that needs to be polled for readiness */
    bool need_ready_poll;

    /* Socket options */
    in_addr_t ip_multicast_if;
    unsigned char ip_multicast_ttl;
    struct linger so_linger;
    bool so_timestamp;
    bool so_timestampns;
    int so_timestamping;
    struct exa_timeo so_sndtimeo;
    struct exa_timeo so_rcvtimeo;

    /* Timestamp generation enable state */
    bool rx_sw_timestamp;

    /* Timestamp reporting enable state */
    bool report_timestamp;

    /* Record of epoll instance membership for non-bypass sockets
     * To be removed when a socket is put into bypass mode */
    unsigned num_epoll_fd;
    int epoll_fd[MAX_NUM_EPOLL];

    /* Non-null if this is an epoll file descriptor */
    struct exa_notify *notify;

    /* Membership of exa_notify instances */
    struct exa_notify *notify_parent;
};

#define EXA_HASHTABLE_SIZE_LOG2 16

struct exa_hashtable
{
    int table[1 << EXA_HASHTABLE_SIZE_LOG2];

    /* Write lock is held when modifying the hash table.
     * Hash table lookups are lockfree */
    uint32_t write_lock;
};

struct exa_socket_list
{
    struct exa_socket *head;
};

extern struct exa_socket *exa_socket_table;
extern size_t exa_socket_table_size;

/* Poll lock protects the hardware rx buffer and related structs
 * The holder of the lock must poll for new packets in the rx buffer */
extern uint32_t exasock_poll_lock __attribute__((aligned (64)));

static inline struct exa_socket *
exa_socket_get(int fd)
{
    if (fd < 0 || fd >= exa_socket_table_size)
        return NULL;
    else
        return exa_socket_table + fd;
}

static inline int
exa_socket_fd(struct exa_socket *sock)
{
    return sock - exa_socket_table;
}

static inline void
exa_hashtable_init(struct exa_hashtable * restrict ht)
{
    memset(ht->table, -1, sizeof(ht->table));
    ht->write_lock = 0;
}

static inline uint32_t
exa_endpoint_hash(struct exa_endpoint * restrict e)
{
    uint32_t a = e->addr.local;
    uint32_t b = e->addr.peer;
    uint32_t c = ((uint32_t)e->port.peer << 16) | e->port.local;

    /* Based on final stage of the lookup3 hash function by Bob Jenkins.
     * http://burtleburtle.net/bob/c/lookup3.c */
#define rot(x, k) (((x) << (k)) | ((x) >> (32-(k))))
    c ^= b; c -= rot(b, 14);
    a ^= c; a -= rot(c, 11);
    b ^= a; b -= rot(a, 25);
    c ^= b; c -= rot(b, 16);
    a ^= c; a -= rot(c, 4);
    b ^= a; b -= rot(a, 14);
    c ^= b; c -= rot(b, 24);
#undef rot

    return c;
}

static inline void
exa_hashtable_insert(struct exa_hashtable * restrict ht, int fd)
{
    struct exa_socket * restrict sock = exa_socket_get(fd);
    uint32_t idx = exa_endpoint_hash(&sock->bind.ip) &
        ((1 << EXA_HASHTABLE_SIZE_LOG2) - 1);

    exa_lock(&ht->write_lock);
    sock->hashtable_next_fd = ht->table[idx];
    ht->table[idx] = fd;
    exa_unlock(&ht->write_lock);
}

static inline void
exa_hashtable_remove(struct exa_hashtable * restrict ht, int remove_fd)
{
    struct exa_socket * restrict remove_sock = exa_socket_get(remove_fd);
    uint32_t idx = exa_endpoint_hash(&remove_sock->bind.ip) &
        ((1 << EXA_HASHTABLE_SIZE_LOG2) - 1);
    int fd;

    exa_lock(&ht->write_lock);

    if (ht->table[idx] == remove_fd)
    {
        ht->table[idx] = remove_sock->hashtable_next_fd;
        exa_unlock(&ht->write_lock);
        return;
    }

    fd = ht->table[idx];
    while (fd != -1)
    {
        struct exa_socket * restrict sock = exa_socket_get(fd);
        if (sock->hashtable_next_fd == remove_fd)
        {
            sock->hashtable_next_fd = remove_sock->hashtable_next_fd;
            exa_unlock(&ht->write_lock);
            return;
        }
    }

    assert(false);
}

static inline int
exa_hashtable_lookup(struct exa_hashtable * restrict ht,
                     struct exa_endpoint * restrict e)
{
    struct exa_endpoint ep = *e;
    uint32_t idx;
    int fd;

    /* Look up by (local addr, local port, peer addr, peer port) */
    idx = exa_endpoint_hash(&ep) & ((1 << EXA_HASHTABLE_SIZE_LOG2) - 1);
    fd = ht->table[idx];
    while (fd != -1)
    {
        struct exa_socket * restrict sock = exa_socket_get(fd);

        if (sock->bind.ip.addr.local == e->addr.local &&
            sock->bind.ip.addr.peer == e->addr.peer &&
            sock->bind.ip.port.local == e->port.local &&
            sock->bind.ip.port.peer == e->port.peer)
            return fd;

        fd = sock->hashtable_next_fd;
    }

    /* Look up by (local addr, local port) */
    ep.addr.peer = htonl(INADDR_ANY);
    ep.port.peer = 0;
    idx = exa_endpoint_hash(&ep) & ((1 << EXA_HASHTABLE_SIZE_LOG2) - 1);
    fd = ht->table[idx];
    while (fd != -1)
    {
        struct exa_socket * restrict sock = exa_socket_get(fd);

        if (sock->bind.ip.addr.local == e->addr.local &&
            sock->bind.ip.addr.peer == htonl(INADDR_ANY) &&
            sock->bind.ip.port.local == e->port.local &&
            sock->bind.ip.port.peer == 0)
            return fd;

        fd = sock->hashtable_next_fd;
    }

    /* Look up by local port only */
    ep.addr.local = htonl(INADDR_ANY);
    idx = exa_endpoint_hash(&ep) & ((1 << EXA_HASHTABLE_SIZE_LOG2) - 1);
    fd = ht->table[idx];
    while (fd != -1)
    {
        struct exa_socket * restrict sock = exa_socket_get(fd);

        if (sock->bind.ip.addr.local == htonl(INADDR_ANY) &&
            sock->bind.ip.addr.peer == htonl(INADDR_ANY) &&
            sock->bind.ip.port.local == e->port.local &&
            sock->bind.ip.port.peer == 0)
            return fd;

        fd = sock->hashtable_next_fd;
    }

    return -1;
}

static inline void
exa_socket_list_add(struct exa_socket_list * restrict list,
                    struct exa_socket * restrict sock)
{
    assert(sock->list_next == NULL);
    assert(sock->list_prev == NULL);

    if (list->head == NULL)
    {
        /* First item in list */
        sock->list_next = sock->list_prev = sock;
        list->head = sock;
    }
    else
    {
        /* Insert after existing items in list */
        struct exa_socket *next = list->head;
        struct exa_socket *prev = next->list_prev;
        sock->list_next = next;
        sock->list_prev = prev;
        prev->list_next = sock;
        next->list_prev = sock;
    }
}

static inline void
exa_socket_list_del(struct exa_socket_list * restrict list,
                    struct exa_socket * restrict sock)
{
    assert(sock->list_next != NULL);
    assert(sock->list_prev != NULL);

    if (sock->list_next == sock)
    {
        /* Only item in list */
        assert(list->head == sock);
        list->head = NULL;
        sock->list_next = sock->list_prev = NULL;
    }
    else
    {
        /* Other items exist */
        if (list->head == sock)
            list->head = sock->list_next;
        sock->list_prev->list_next = sock->list_next;
        sock->list_next->list_prev = sock->list_prev;
        sock->list_prev = sock->list_next = NULL;
    }
}

static inline struct exa_socket *
exa_socket_list_begin(struct exa_socket_list * restrict list)
{
    return list->head;
}

static inline struct exa_socket *
exa_socket_list_next(struct exa_socket_list * restrict list,
                     struct exa_socket * restrict sock)
{
    if (sock->list_next != list->head)
        return sock->list_next;
    else
        return NULL;
}

#endif /* STRUCTS_H_562CD82818334BCAAEA0F7C939E7DDA3 */
