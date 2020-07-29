#ifndef EXASOCK_SOCKET_OVERRIDE_H
#define EXASOCK_SOCKET_OVERRIDE_H

#ifdef MSG_WAITFORONE
#define HAVE_RECVMMSG
#endif

extern int (*__libc_socket)(int, int, int);
extern int (*__libc_close)(int);
extern int (*__libc_bind)(int, const struct sockaddr *, socklen_t);
extern int (*__libc_listen)(int, int);
extern int (*__libc_accept)(int, struct sockaddr *, socklen_t *);
extern int (*__libc_accept4)(int, struct sockaddr *, socklen_t *, int);
extern int (*__libc_connect)(int, const struct sockaddr *, socklen_t);
extern int (*__libc_shutdown)(int, int);
extern int (*__libc_fcntl)(int, int, ...);
extern int (*__libc_ioctl)(int d, int request, void *argp);
extern int (*__libc_getsockname)(int, struct sockaddr *, socklen_t *);
extern int (*__libc_getpeername)(int, struct sockaddr *, socklen_t *);
extern int (*__libc_getsockopt)(int, int, int, void *, socklen_t *);
extern int (*__libc_setsockopt)(int, int, int, const void *, socklen_t);
extern ssize_t (*__libc_recv)(int, void *, size_t, int);
extern ssize_t (*__libc_recv_chk)(int, void *, size_t, size_t, int);
extern ssize_t (*__libc_recvfrom)(int, void *, size_t, int, struct sockaddr *,
                                  socklen_t *);
extern ssize_t (*__libc_recvfrom_chk)(int, void *, size_t, size_t, int,
                                      struct sockaddr *, socklen_t *);
extern ssize_t (*__libc_recvmsg)(int, struct msghdr *, int);
extern ssize_t (*__libc_send)(int, const void *, size_t, int);
extern ssize_t (*__libc_sendto)(int, const void *, size_t, int,
                                const struct sockaddr *, socklen_t);
extern ssize_t (*__libc_sendmsg)(int, const struct msghdr *, int);
extern int (*__libc_sendmmsg)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                              int flags);
extern ssize_t (*__libc_read)(int, void *, size_t);
extern ssize_t (*__libc_readv)(int, const struct iovec *iov, int iovcnt);
extern ssize_t (*__libc_read_chk)(int, void *, size_t, size_t);
extern ssize_t (*__libc_write)(int, const void *, size_t);
extern ssize_t (*__libc_writev)(int, const struct iovec *iov, int iovcnt);
extern int (*__libc_select)(int, fd_set *, fd_set *, fd_set *,
                            struct timeval *);
extern int (*__libc_pselect)(int, fd_set *, fd_set *, fd_set *,
                             const struct timespec *, const sigset_t *);
extern int (*__libc_poll)(struct pollfd *, nfds_t, int);
extern int (*__libc_ppoll)(struct pollfd *, nfds_t, const struct timespec *,
                           const sigset_t *);
extern sighandler_t (*__libc_signal)(int, sighandler_t);
extern int (*__libc_sigaction)(int, const struct sigaction *,
                               struct sigaction *);
extern int (*__libc_siginterrupt)(int, int);
extern int (*__libc_epoll_create)(int);
extern int (*__libc_epoll_create1)(int);
extern int (*__libc_epoll_ctl)(int, int, int, struct epoll_event *);
extern int (*__libc_epoll_wait)(int, struct epoll_event *, int, int);
extern int (*__libc_epoll_pwait)(int, struct epoll_event *, int, int,
                                 const sigset_t *);
#ifdef HAVE_RECVMMSG
extern int (*__libc_recvmmsg)(int, struct mmsghdr *, unsigned int, int,
#if RECVMMSG_HAS_CONST_TIMESPEC
                              const
#endif
                              struct timespec *);
#endif

void __exasock_override_init(void);

struct exa_socket;

extern bool __thread signal_received;
extern bool __thread signal_interrupted;

extern bool __thread override_disabled;
extern bool __thread override_unsafe;
extern bool __override_initialized;

#define LIBC(func, ...)                 \
    ({                                  \
        if (!__override_initialized)    \
            __exasock_override_init();  \
        __libc_##func(__VA_ARGS__);     \
    })

#endif /* EXASOCK_SOCKET_OVERRIDE_H */
