#include "common.h"

#include <netinet/ether.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <poll.h>

#include "kernel/api.h"
#include "kernel/structs.h"
#include "override.h"
#include "lock.h"
#include "rwlock.h"
#include "structs.h"
#include "sys.h"

#define MAX_MSG_SIZE 4096

/* Call libc directly instead of calling our wrappers */

static int                              exasock_fd;
static struct exasock_kernel_info *     exasock_kernel_info;

unsigned int                            exa_dst_table_size;
struct exa_dst_entry *                  exa_dst_table;
uint8_t *                               exa_dst_used_flags;

static void
err_exit(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "exasock: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);

    exit(EXIT_FAILURE);
}

__attribute__((constructor))
void
__exasock_sys_init()
{
    int fd;
    void *ptr;

    fd = open(EXASOCK_DEVICE, O_RDWR);
    if (fd == -1)
        err_exit("could not open " EXASOCK_DEVICE ": %s",
                 strerror(errno));

    exasock_fd = fd;

    ptr = mmap(NULL, EXASOCK_KERNEL_INFO_SIZE, PROT_READ, MAP_SHARED,
               exasock_fd, EXASOCK_OFFSET_KERNEL_INFO);
    if (ptr == MAP_FAILED)
        err_exit("could not mmap info page: %s", strerror(errno));
    exasock_kernel_info = ptr;

    if (exasock_kernel_info->api_version != EXASOCK_API_VERSION)
        err_exit("incorrect kernel api version: %d (%d required)",
                 exasock_kernel_info->api_version, EXASOCK_API_VERSION);

    exa_dst_table_size = exasock_kernel_info->dst_table_size;

    ptr = mmap(NULL, exa_dst_table_size * sizeof(struct exa_dst_entry),
               PROT_READ, MAP_SHARED, exasock_fd, EXASOCK_OFFSET_DST_TABLE);
    if (ptr == MAP_FAILED)
        err_exit("could not mmap destination table: %s", strerror(errno));
    exa_dst_table = ptr;

    ptr = mmap(NULL, exa_dst_table_size * sizeof(uint8_t), PROT_WRITE,
               MAP_SHARED, exasock_fd, EXASOCK_OFFSET_DST_USED_FLAGS);
    if (ptr == MAP_FAILED)
        err_exit("could not mmap destination table flags: %s", strerror(errno));
    exa_dst_used_flags = ptr;
}

void
exa_sys_dst_queue(in_addr_t dst_addr, in_addr_t src_addr, char *hdr,
                  size_t hdr_len, const struct iovec * restrict iov,
                  size_t iovcnt, size_t skip_len, size_t data_len, bool warm)
{
    struct exasock_dst_request req;
    char buf[MAX_MSG_SIZE];
    size_t offs;
    size_t i;
    size_t frame_len = hdr_len + data_len;
    size_t iov_len = skip_len + data_len;
    char *p;

    if (frame_len > MAX_MSG_SIZE)
        return;

    memcpy(buf, hdr, hdr_len);

    offs = 0;
    p = buf + hdr_len;
    for (i = 0; i < iovcnt && offs < iov_len; i++)
    {
        size_t len = iov[i].iov_len < iov_len - offs
                   ? iov[i].iov_len : iov_len - offs;
        size_t skip = offs < skip_len ? skip_len - offs : 0;
        if (skip < len)
        {
            memcpy(p, iov[i].iov_base + skip, len - skip);
            p += len - skip;
        }
        offs += len;
    }
    assert(offs == iov_len);

    memset(&req, 0, sizeof(req));
    req.dst_addr = dst_addr;
    req.src_addr = src_addr;
    req.ip_packet = buf;
    if (EXPECT_TRUE(!warm))
        req.ip_packet_len = hdr_len + offs;
    else
        req.ip_packet_len = 0;

    exasock_override_off();
    ioctl(exasock_fd, EXASOCK_IOCTL_DST_QUEUE, &req);
    exasock_override_on();
}

int
exa_sys_dst_request(in_addr_t dst_addr, in_addr_t *src_addr)
{
    struct exasock_dst_request req;

    assert(src_addr != NULL);

    memset(&req, 0, sizeof(req));
    req.dst_addr = dst_addr;
    req.src_addr = *src_addr;
    req.ip_packet = NULL;
    req.ip_packet_len = 0;

    exasock_override_off();

    /* EXASOCK_IOCTL_DST_QUEUE returns ENETUNREACH if the route does not
     * go via an ExaNIC interface */
    if (ioctl(exasock_fd, EXASOCK_IOCTL_DST_QUEUE, &req) != 0)
        goto err_ioctl;

    *src_addr = req.src_addr;

    exasock_override_on();
    return 0;

err_ioctl:
    exasock_override_on();
    return -1;
}

/* Open the exasock device file to replace the given native socket */
int
exa_sys_exasock_open(int native_fd)
{
    int exasock_fd;
    int flags;

    exasock_override_off();
    flags = fcntl(native_fd, F_GETFL);

    exasock_fd = open(EXASOCK_DEVICE, O_RDWR);
    if (exasock_fd == -1)
        goto err_open;

    if (ioctl(exasock_fd, EXASOCK_IOCTL_SOCKET, &native_fd) != 0)
        goto err_ioctl;

    if (flags != -1)
        fcntl(exasock_fd, F_SETFL, flags);

    exasock_override_on();
    return exasock_fd;

err_ioctl:
    close(exasock_fd);
err_open:
    exasock_override_on();
    return -1;
}

/* Replace the native socket file descriptor with the exasock file descriptor */
int
exa_sys_replace_fd(int native_fd, int exasock_fd)
{
    int flags;

    exasock_override_off();
    flags = fcntl(native_fd, F_GETFD);

    if (dup2(exasock_fd, native_fd) == -1)
        goto err_dup2;

    if (flags != -1)
        fcntl(native_fd, F_SETFD, flags);

    close(exasock_fd);

    exasock_override_on();
    return 0;

err_dup2:
    exasock_override_on();
    return -1;
}

/* Send a bind request to the kernel module */
int
exa_sys_bind(int fd, struct exa_endpoint * restrict endpoint)
{
    struct exasock_endpoint req;

    exasock_override_off();

    memset(&req, 0, sizeof(req));
    req.local_addr = endpoint->addr.local;
    req.local_port = endpoint->port.local;

    if (ioctl(fd, EXASOCK_IOCTL_BIND, &req) != 0)
        goto err_ioctl;

    if (endpoint->port.local == 0)
        endpoint->port.local = req.local_port;

    exasock_override_on();
    return 0;

err_ioctl:
    exasock_override_on();
    return -1;
}

/* Send a connect request to the kernel module */
int
exa_sys_connect(int fd, struct exa_endpoint * restrict endpoint)
{
    struct exasock_endpoint req;

    exasock_override_off();

    memset(&req, 0, sizeof(req));
    req.peer_addr = endpoint->addr.peer;
    req.peer_port = endpoint->port.peer;

    if (ioctl(fd, EXASOCK_IOCTL_CONNECT, &req) != 0)
        goto err_ioctl;

    if (endpoint->addr.local == 0)
        endpoint->addr.local = req.local_addr;
    if (endpoint->port.local == 0)
        endpoint->port.local = req.local_port;

    exasock_override_on();
    return 0;

err_ioctl:
    exasock_override_on();
    return -1;
}

/* Update endpoint address and port in kernel module */
int
exa_sys_update(int fd, struct exa_endpoint * restrict endpoint)
{
    struct exasock_endpoint req;

    exasock_override_off();

    memset(&req, 0, sizeof(req));
    req.local_addr = endpoint->addr.local;
    req.peer_addr = endpoint->addr.peer;
    req.local_port = endpoint->port.local;
    req.peer_port = endpoint->port.peer;

    if (ioctl(fd, EXASOCK_IOCTL_UPDATE, &req) != 0)
        goto err_ioctl;

    exasock_override_on();
    return 0;

err_ioctl:
    exasock_override_on();
    return -1;
}

/* Map the kernel allocated buffers */
int
exa_sys_buffer_mmap(int fd, struct exa_socket_state **state,
                    char **rx_buf, char **tx_buf)
{
    struct exa_socket_state *s;
    char *r = NULL, *t = NULL;

    s = mmap(NULL, EXASOCK_SOCKET_STATE_SIZE, PROT_READ | PROT_WRITE,
            MAP_SHARED, fd, EXASOCK_OFFSET_SOCKET_STATE);
    if (s == MAP_FAILED)
        goto err_mmap_socket_state;

    if (s->rx_buffer_size > 0)
    {
        r = mmap(NULL, s->rx_buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                fd, EXASOCK_OFFSET_RX_BUFFER);
        if (r == MAP_FAILED)
            goto err_mmap_rx_buffer;
    }

    if (s->tx_buffer_size > 0)
    {
        t = mmap(NULL, s->tx_buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                fd, EXASOCK_OFFSET_TX_BUFFER);
        if (t == MAP_FAILED)
            goto err_mmap_tx_buffer;
    }

    *state = s;
    *rx_buf = r;
    *tx_buf = t;
    return 0;

err_mmap_tx_buffer:
    munmap(r, s->rx_buffer_size);
err_mmap_rx_buffer:
    munmap(s, EXASOCK_SOCKET_STATE_SIZE);
err_mmap_socket_state:
    return -1;
}

/* Unmap the kernel allocated buffers */
void
exa_sys_buffer_munmap(int fd, struct exa_socket_state **state,
                      char **rx_buf, char **tx_buf)
{
    struct exa_socket_state *s = *state;
    char *r = *rx_buf, *t = *tx_buf;

    if (s->rx_buffer_size > 0)
        munmap(r, s->rx_buffer_size);
    if (s->tx_buffer_size > 0)
        munmap(t, s->tx_buffer_size);
    munmap(s, EXASOCK_SOCKET_STATE_SIZE);

    *state = NULL;
    *rx_buf = NULL;
    *tx_buf = NULL;
}

int
exa_sys_setsockopt(int fd, int level, int optname, const void *optval,
                   socklen_t optlen)
{
    struct exasock_opt_request req;
    int ret;

    req.level = level;
    req.optname = optname;
    req.optval = (void *)optval;
    req.optlen = optlen;

    exasock_override_off();
    ret = ioctl(fd, EXASOCK_IOCTL_SETSOCKOPT, &req);
    exasock_override_on();

    return ret;
}

int
exa_sys_getsockopt(int fd, int level, int optname, void *optval,
                   socklen_t *optlen)
{
    struct exasock_opt_request req;
    int ret;

    req.level = level;
    req.optname = optname;
    req.optval = optval;
    req.optlen = *optlen;

    exasock_override_off();
    ret = ioctl(fd, EXASOCK_IOCTL_GETSOCKOPT, &req);
    exasock_override_on();

    *optlen = req.optlen;
    return ret;
}

int
exa_sys_epoll_create(void)
{
    int fd;

    exasock_override_off();
    fd = open(EXASOCK_DEVICE, O_RDWR);
    if (fd == -1)
        goto err_open;

    if (ioctl(fd, EXASOCK_IOCTL_EPOLL_CREATE, NULL) != 0)
        goto err_ioctl;

    exasock_override_on();
    return fd;

err_ioctl:
    close(fd);
err_open:
    exasock_override_on();
    return -1;
}

int
exa_sys_epoll_close(int fd)
{
    int ret;

    exasock_override_off();
    ret = close(fd);
    exasock_override_on();
    return ret;
}

/* Map the kernel allocated epoll state */
int
exa_sys_epoll_mmap(int fd, struct exasock_epoll_state **state)
{
    struct exasock_epoll_state *s;

    s = mmap(NULL, EXASOCK_EPOLL_STATE_SIZE, PROT_READ | PROT_WRITE,
            MAP_SHARED, fd, EXASOCK_OFFSET_EPOLL_STATE);
    if (s == MAP_FAILED)
        return -1;

    *state = s;
    return 0;
}

/* Unmap the kernel allocated epoll state */
void
exa_sys_epoll_munmap(int fd, struct exasock_epoll_state **state)
{
    struct exasock_epoll_state *s = *state;

    munmap(s, EXASOCK_EPOLL_STATE_SIZE);

    *state = NULL;
}

int
exa_sys_epoll_ctl(int epfd, enum exasock_epoll_ctl_op op, int fd)
{
    struct exasock_epoll_ctl_request req;
    int ret;

    memset(&req, 0, sizeof(req));
    req.op = op;
    req.fd = fd;

    exasock_override_off();
    ret = ioctl(epfd, EXASOCK_IOCTL_EPOLL_CTL, &req);
    exasock_override_on();

    return ret;
}

int
exa_sys_ate_enable(int fd, int ate_id)
{
    int ret;

    exasock_override_off();
    ret = ioctl(fd, EXASOCK_IOCTL_ATE_ENABLE, &ate_id);
    exasock_override_on();

    return ret;
}

int
exa_sys_ate_init(int fd)
{
    int ret;

    exasock_override_off();
    ret = ioctl(fd, EXASOCK_IOCTL_ATE_INIT, NULL);
    exasock_override_on();

    return ret;
}

int
exa_sys_get_isn(int fd, uint32_t *isn)
{
    int ret;

    exasock_override_off();
    ret = ioctl(fd, EXASOCK_IOCTL_ISN_ALLOC, isn);
    exasock_override_on();

    return ret;
}

pid_t
exa_sys_get_tid()
{
#ifdef SYS_gettid
    return syscall(SYS_gettid);
#else
#warning "gettid system call is unavailable!"
#warning "exasock trace output will not look correct."
    return getpid();
#endif
}
