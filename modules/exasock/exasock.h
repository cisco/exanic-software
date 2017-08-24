/**
 * Kernel support for the ExaSock library
 * Copyright (C) 2011-2017 Exablaze Pty Ltd and its licensors
 */

#ifndef _EXASOCK_H_
#define _EXASOCK_H_

#include <net/neighbour.h>

enum exasock_type
{
    EXASOCK_TYPE_SOCKET,
    EXASOCK_TYPE_EPOLL
};

struct exasock_hdr_socket
{
    int domain;
    int type;
};

struct exasock_hdr
{
    enum exasock_type type;
    struct exasock_hdr_socket socket;
};

struct exasock_epoll
{
    enum exasock_type type;
    struct exasock_epoll_state *user_page;
    struct list_head fd_ready_backlog_list;
};

struct exasock_epoll_notify
{
    struct exasock_epoll *epoll;
    int fd;
    struct list_head node;
};

/* Return 1 if lock successful, 0 if unsuccessful */
static inline int exasock_trylock(volatile uint32_t *flag)
{
    return xchg(flag, 1) == 0;
}

static inline void exasock_unlock(volatile uint32_t *flag)
{
    *flag = 0;
}

/* exasock-dst.c */
int __init exasock_dst_init(void);
void exasock_dst_exit(void);
void exasock_dst_remove_socket(uint32_t local_addr, uint32_t peer_addr,
                               uint16_t local_port, uint16_t peer_port);
void exasock_dst_neigh_update(struct neighbour *neigh);
int exasock_dst_insert(uint32_t dst_addr, uint32_t *src_addr, int *ifindex,
                       struct sk_buff *skb);
void exasock_dst_invalidate_src(uint32_t src_addr);
int exasock_dst_used_flags_mmap(struct vm_area_struct *vma);
int exasock_dst_table_mmap(struct vm_area_struct *vma);
unsigned int exasock_dst_table_size(void);

/* exasock-ip.c */
int exasock_ip_send(uint8_t proto, uint32_t dst_addr, uint32_t src_addr,
                    struct sk_buff *skb);

/* exasock-udp.c */
struct exasock_udp;

int __init exasock_udp_init(void);
void exasock_udp_exit(void);
struct exasock_udp *exasock_udp_alloc(struct socket *sock, int fd);
int exasock_udp_bind(struct exasock_udp *udp, uint32_t local_addr,
                     uint16_t *local_port);
int exasock_udp_connect(struct exasock_udp *udp, uint32_t *local_addr,
                        uint16_t *local_port, uint32_t peer_addr,
                        uint16_t peer_port);
void exasock_udp_free(struct exasock_udp *udp);
int exasock_udp_rx_mmap(struct exasock_udp *udp, struct vm_area_struct *vma);
int exasock_udp_state_mmap(struct exasock_udp *udp, struct vm_area_struct *vma);
int exasock_udp_setsockopt(struct exasock_udp *udp, int level, int optname,
                           char __user *optval, unsigned int optlen);
int exasock_udp_getsockopt(struct exasock_udp *udp, int level, int optname,
                           char __user *optval, unsigned int *optlen);

/* exasock-tcp.c */
struct exasock_tcp;

int __init exasock_tcp_init(void);
void exasock_tcp_exit(void);
struct exasock_tcp *exasock_tcp_alloc(struct socket *sock, int fd);
int exasock_tcp_bind(struct exasock_tcp *tcp, uint32_t local_addr,
                     uint16_t *local_port);
void exasock_tcp_update(struct exasock_tcp *tcp,
                        uint32_t local_addr, uint16_t local_port,
                        uint32_t peer_addr, uint16_t peer_port);
void exasock_tcp_free(struct exasock_tcp *tcp);
int exasock_tcp_rx_mmap(struct exasock_tcp *tcp, struct vm_area_struct *vma);
int exasock_tcp_tx_mmap(struct exasock_tcp *tcp, struct vm_area_struct *vma);
int exasock_tcp_state_mmap(struct exasock_tcp *tcp, struct vm_area_struct *vma);
int exasock_tcp_setsockopt(struct exasock_tcp *tcp, int level, int optname,
                           char __user *optval, unsigned int optlen);
int exasock_tcp_getsockopt(struct exasock_tcp *tcp, int level, int optname,
                           char __user *optval, unsigned int *optlen);
int exasock_tcp_notify_add(uint32_t local_addr, uint16_t local_port,
                           struct exasock_epoll_notify *notify);
int exasock_tcp_notify_del(uint32_t local_addr, uint16_t local_port,
                           struct exasock_epoll_notify **notify);

/* exasock-epoll.c */
struct exasock_epoll *exasock_epoll_alloc(void);
int exasock_epoll_ctl(struct exasock_epoll *epoll, bool add,
                      uint32_t local_addr, uint16_t local_port, int fd);
void exasock_epoll_free(struct exasock_epoll *epoll);
int exasock_epoll_state_mmap(struct exasock_epoll *epoll,
                             struct vm_area_struct *vma);
void exasock_epoll_update(struct exasock_epoll_notify *notify);

#endif /* _EXASOCK_H_ */
