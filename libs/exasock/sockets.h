#ifndef EXASOCK_SOCKETS_H
#define EXASOCK_SOCKETS_H

/* Functions for manipulating sockets */
void exa_socket_zero(struct exa_socket * restrict sock);
void exa_socket_init(struct exa_socket * restrict sock, int domain,
                     int type, int protocol);
int exa_socket_ip_memberships_add(struct exa_socket *esk,
                                  const struct exa_mcast_endpoint *emep);
struct exa_mcast_membership *exa_socket_ip_memberships_find(struct exa_socket *esk,
                                                            in_addr_t mc_mcast_addr,
                                                            in_addr_t mc_iface_addr,
                                                            struct exa_mcast_membership **ret_prev);
struct exa_mcast_membership *exa_socket_ip_memberships_remove(struct exa_socket *esk,
                                                           const struct exa_mcast_endpoint *emep);
void exa_socket_ip_memberships_free(struct exa_mcast_membership *obj);

static inline void
exa_socket_ip_memberships_remove_and_free(struct exa_socket *esk,
                                          const struct exa_mcast_endpoint *emep)
{
    struct exa_mcast_membership *tmp;

    tmp = exa_socket_ip_memberships_remove(esk, emep);
    if (tmp != NULL)
        exa_socket_ip_memberships_free(tmp);
}

void exa_socket_ip_memberships_remove_and_free_all(struct exa_socket *esk);
int exa_socket_update_interfaces(struct exa_socket * restrict sock, in_addr_t addr);
void exa_socket_update_timestamping(struct exa_socket * restrict sock);
int exa_socket_get_tcp_keepintvl(struct exa_socket * restrict sock);
int exa_socket_get_tcp_keepcnt(struct exa_socket * restrict sock);
int exa_socket_get_tcp_keepidle(struct exa_socket * restrict sock);
void exa_socket_tcp_update_keepalive(struct exa_socket * restrict sock);
void exa_socket_tcp_update_user_timeout(struct exa_socket * restrict sock);
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
void exa_socket_udp_remove(struct exa_socket * restrict sock);
void exa_socket_udp_free(struct exa_socket * restrict sock);

struct exa_tcp_init_state;
int exa_socket_tcp_bind(struct exa_socket * restrict sock, in_addr_t addr,
                        in_port_t port);
int exa_socket_tcp_connect(struct exa_socket * restrict sock, in_addr_t addr,
                           in_port_t port);
int exa_socket_tcp_listen(struct exa_socket * restrict sock, int backlog);
int exa_socket_tcp_accept(struct exa_endpoint * restrict endpoint,
                          struct exa_tcp_init_state * restrict tcp_state);
void exa_socket_tcp_remove(struct exa_socket * restrict sock);
void exa_socket_tcp_free(struct exa_socket * restrict sock);

#endif /* EXASOCK_SOCKETS_H */
