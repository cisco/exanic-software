#ifndef OVERRIDE_H_DC43521EC0204430846EB44C89D56BB9
#define OVERRIDE_H_DC43521EC0204430846EB44C89D56BB9

extern int (*libc_socket)(int, int, int);
extern int (*libc_close)(int);
extern int (*libc_bind)(int, const struct sockaddr *, socklen_t);
extern int (*libc_listen)(int, int);
extern int (*libc_accept)(int, struct sockaddr *, socklen_t *);
extern int (*libc_accept4)(int, struct sockaddr *, socklen_t *, int);
extern int (*libc_connect)(int, const struct sockaddr *, socklen_t);
extern int (*libc_shutdown)(int, int);
extern int (*libc_fcntl)(int, int, ...);
extern int (*libc_ioctl)(int d, int request, void *argp);
extern int (*libc_getsockname)(int, struct sockaddr *, socklen_t *);
extern int (*libc_getpeername)(int, struct sockaddr *, socklen_t *);
extern int (*libc_getsockopt)(int, int, int, void *, socklen_t *);
extern int (*libc_setsockopt)(int, int, int, const void *, socklen_t);
extern ssize_t (*libc_recv)(int, void *, size_t, int);
extern ssize_t (*libc_recv_chk)(int, void *, size_t, size_t, int);
extern ssize_t (*libc_recvfrom)(int, void *, size_t, int, struct sockaddr *,
                                socklen_t *);
extern ssize_t (*libc_recvfrom_chk)(int, void *, size_t, size_t, int,
                                    struct sockaddr *, socklen_t *);
extern ssize_t (*libc_recvmsg)(int, struct msghdr *, int);
extern ssize_t (*libc_send)(int, const void *, size_t, int);
extern ssize_t (*libc_sendto)(int, const void *, size_t, int,
                              const struct sockaddr *, socklen_t);
extern ssize_t (*libc_sendmsg)(int, const struct msghdr *, int);
extern ssize_t (*libc_read)(int, void *, size_t);
extern ssize_t (*libc_readv)(int, const struct iovec *iov, int iovcnt);
extern ssize_t (*libc_read_chk)(int, void *, size_t, size_t);
extern ssize_t (*libc_write)(int, const void *, size_t);
extern ssize_t (*libc_writev)(int, const struct iovec *iov, int iovcnt);
extern int (*libc_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
extern int (*libc_pselect)(int, fd_set *, fd_set *, fd_set *,
                           const struct timespec *, const sigset_t *);
extern int (*libc_poll)(struct pollfd *, nfds_t, int);
extern int (*libc_ppoll)(struct pollfd *, nfds_t, const struct timespec *,
                         const sigset_t *);
extern sighandler_t (*libc_signal)(int, sighandler_t);
extern int (*libc_sigaction)(int, const struct sigaction *, struct sigaction *);
extern int (*libc_siginterrupt)(int, int);
extern int (*libc_epoll_create)(int);
extern int (*libc_epoll_create1)(int);
extern int (*libc_epoll_ctl)(int, int, int, struct epoll_event *);
extern int (*libc_epoll_wait)(int, struct epoll_event *, int, int);
extern int (*libc_epoll_pwait)(int, struct epoll_event *, int, int, const sigset_t *);

struct exa_socket;

extern bool __thread signal_received;
extern bool __thread signal_interrupted;

extern bool __thread override_disabled;

#endif /* OVERRIDE_H_DC43521EC0204430846EB44C89D56BB9 */
