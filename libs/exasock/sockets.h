#ifndef EXASOCK_SOCKETS_H
#define EXASOCK_SOCKETS_H

/* Functions for manipulating sockets */
void exa_socket_zero(struct exa_socket * restrict sock);
void exa_socket_init(struct exa_socket * restrict sock, int domain,
                     int type, int protocol);
int exa_socket_update_interfaces(struct exa_socket * restrict sock, in_addr_t addr);
void exa_socket_update_timestamping(struct exa_socket * restrict sock);
int exa_socket_get_tcp_keepintvl(struct exa_socket * restrict sock);
int exa_socket_get_tcp_keepcnt(struct exa_socket * restrict sock);
int exa_socket_get_tcp_keepidle(struct exa_socket * restrict sock);
void exa_socket_tcp_update_keepalive(struct exa_socket * restrict sock);
int exa_socket_enable_bypass(struct exa_socket * restrict sock);
int exa_socket_del_mcast(struct exa_socket * restrict sock,
                         struct exa_mcast_endpoint * restrict mc_ep);
int exa_socket_add_mcast(struct exa_socket * restrict sock,
                         struct exa_mcast_endpoint * restrict mc_ep);

int exa_socket_udp_bind(struct exa_socket * restrict sock, in_addr_t addr,
                        in_port_t port);
int exa_socket_udp_connect(struct exa_socket * restrict sock, in_addr_t addr,
                           in_port_t port);
int exa_socket_udp_target(struct exa_socket * restrict sock, in_addr_t addr,
                          in_port_t port);
void exa_socket_udp_close(struct exa_socket * restrict sock);

struct exa_tcp_init_state;
int exa_socket_tcp_bind(struct exa_socket * restrict sock, in_addr_t addr,
                        in_port_t port);
int exa_socket_tcp_connect(struct exa_socket * restrict sock, in_addr_t addr,
                           in_port_t port);
int exa_socket_tcp_listen(struct exa_socket * restrict sock, int backlog);
int exa_socket_tcp_accept(struct exa_endpoint * restrict endpoint,
                          struct exa_tcp_init_state * restrict tcp_state);
void exa_socket_tcp_close(struct exa_socket * restrict sock);

#endif /* EXASOCK_SOCKETS_H */
