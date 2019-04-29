#ifndef EXASOCK_SYS_H
#define EXASOCK_SYS_H

extern unsigned int             exa_dst_table_size;
extern struct exa_dst_entry *   exa_dst_table;
extern uint8_t *                exa_dst_used_flags;

/* Functions for communicating with the kernel component of Exasock */

void exa_sys_dst_queue(in_addr_t ip_addr, in_addr_t src_addr, char *hdr,
                       size_t hdr_len, const struct iovec * restrict iov,
                       size_t iovcnt, size_t skip_len, size_t data_len,
                       bool warm);
int exa_sys_dst_request(in_addr_t dst_addr, in_addr_t *src_addr);

int exa_sys_exasock_open(int native_fd);
int exa_sys_replace_fd(int native_fd, int exasock_fd);

int exa_sys_bind(int fd, struct exa_endpoint * restrict endpoint);
int exa_sys_connect(int fd, struct exa_endpoint * restrict endpoint);
int exa_sys_listen(int fd, struct exa_endpoint * restrict endpoint);
int exa_sys_update(int fd, struct exa_endpoint * restrict endpoint);

struct exa_socket_state;

int exa_sys_buffer_mmap(int fd, struct exa_socket_state **state,
                        char **rx_buf, char **tx_buf);
void exa_sys_buffer_munmap(int fd, struct exa_socket_state **state,
                           char **rx_buf, char **tx_buf);

int exa_sys_setsockopt(int fd, int level, int optname, const void *optval,
                       socklen_t optlen);
int exa_sys_getsockopt(int fd, int level, int optname, void *optval,
                       socklen_t *optlen);

int exa_sys_epoll_create(void);
int exa_sys_epoll_close(int fd);
int exa_sys_epoll_mmap(int fd, struct exasock_epoll_state **state);
void exa_sys_epoll_munmap(int fd, struct exasock_epoll_state **state);
int exa_sys_epoll_ctl(int epfd, enum exasock_epoll_ctl_op op, int fd);
int exa_sys_ate_enable(int fd, int ate_id);
int exa_sys_ate_init(int fd);
int exa_sys_get_isn(int fd, uint32_t *isn);

pid_t exa_sys_get_tid();

#endif /* EXASOCK_SYS_H */
