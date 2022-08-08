#ifndef EXASOCK_EXANIC_H
#define EXASOCK_EXANIC_H

struct exanic_ip;
struct exanic_udp;
struct exanic_tcp;
struct exa_socket;
struct exa_endpoint;

bool exanic_ip_find(in_addr_t addr);
bool exanic_ip_find_by_interface(const char *ifname, in_addr_t *addr);
struct exanic_ip *exanic_ip_acquire(in_addr_t addr);
void exanic_ip_acquire_ref(struct exanic_ip *ctx);
void exanic_ip_release(struct exanic_ip *ctx);
void exanic_ip_acquire_all(void);
void exanic_ip_release_all(void);

void exanic_ip_update_timestamping(const char *ifname);

int exanic_poll(int* expected_fd);
void exanic_work(uint64_t now);

/* Functions for sending UDP packets on an ExaNIC */
int exanic_udp_alloc(struct exa_socket * restrict sock);
void exanic_udp_free(struct exa_socket * restrict sock);
void exanic_udp_get_src(struct exa_socket * restrict sock, in_addr_t *addr,
                        in_port_t *port);
void exanic_udp_get_dest(struct exa_socket * restrict sock, in_addr_t *addr,
                         in_port_t *port, uint8_t *ttl);
void exanic_udp_set_src(struct exa_socket * restrict sock,
                        struct exanic_ip * restrict ip_ctx,
                        in_port_t port);
void exanic_udp_set_dest(struct exa_socket * restrict sock,
                         in_addr_t addr, in_port_t port, uint8_t ttl);
void exanic_udp_prepare(struct exa_socket * restrict sock);
ssize_t exanic_udp_send(struct exa_socket * restrict sock, const void *buf,
                        size_t len, bool warm);
ssize_t exanic_udp_send_iov(struct exa_socket * restrict sock,
                            const struct iovec *iov, size_t iovcnt, bool warm);

/* Functions for TCP connections on an ExaNIC */
struct exa_tcp_init_state;
int exanic_tcp_alloc(struct exa_socket * restrict sock);
void exanic_tcp_free(struct exa_socket * restrict sock);
int exanic_tcp_get_device(struct exa_socket * restrict sock, char *dev,
                          size_t len, int *port_number);
void exanic_tcp_listen(struct exa_socket * restrict sock, int backlog);
void exanic_tcp_accept(struct exa_socket * restrict sock,
                       struct exa_endpoint * restrict ep);
void exanic_tcp_connect(struct exa_socket * restrict sock,
                        struct exa_endpoint * restrict ep);
void exanic_tcp_shutdown_write(struct exa_socket * restrict sock);
void exanic_tcp_reset(struct exa_socket * restrict sock);
bool exanic_tcp_connecting(struct exa_socket * restrict sock);
bool exanic_tcp_listening(struct exa_socket * restrict sock);
bool exanic_tcp_writeable(struct exa_socket * restrict sock);
bool exanic_tcp_write_closed(struct exa_socket *sock);
ssize_t exanic_tcp_send(struct exa_socket * restrict sock, const void *buf,
                        size_t len, bool warm);
ssize_t exanic_tcp_send_iov(struct exa_socket * restrict sock,
                            const struct iovec *iov, size_t iovcnt,
                            size_t skip_len, size_t data_len, bool warm);
ssize_t exanic_tcp_build_hdr(struct exa_socket * restrict sock, void *buf,
                             size_t len, bool *conn_closed);

#endif /* EXASOCK_EXANIC_H */
