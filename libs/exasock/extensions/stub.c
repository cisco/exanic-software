#include <unistd.h>
#include <errno.h>

#include <exasock/extensions.h>

__attribute__((visibility("default")))
int
exasock_loaded(void)
{
    return 0;
}

__attribute__((visibility("default")))
uint32_t
exasock_version_code(void)
{
    return 0;
}

__attribute__((visibility("default")))
const char *
exasock_version_text(void)
{
    return NULL;
}

__attribute__((visibility("default")))
int
exasock_tcp_get_device(int fd, char *dev, size_t dev_len, int *port_num)
{
    errno = EOPNOTSUPP;
    return -1;
}

__attribute__((visibility("default")))
ssize_t
exasock_tcp_build_header(int fd, void *buf, size_t len, size_t offset,
                         int flags)
{
    errno = EOPNOTSUPP;
    return -1;
}

__attribute__((visibility("default")))
int
exasock_tcp_set_length(void *hdr, size_t hdr_len, size_t data_len)
{
    errno = EOPNOTSUPP;
    return -1;
}

__attribute__((visibility("default")))
int
exasock_tcp_calc_checksum(void *hdr, size_t hdr_len,
                          const void *data, size_t data_len)
{
    errno = EOPNOTSUPP;
    return -1;
}

__attribute__((visibility("default")))
int
exasock_tcp_send_advance(int fd, const void *buf, size_t len)
{
    errno = EOPNOTSUPP;
    return -1;
}

__attribute__((visibility("default")))
void print_exasock_latencies(void)
{
    errno = EOPNOTSUPP;
}

__attribute__((visibility("default")))
void clear_latencies(void)
{
    errno = EOPNOTSUPP;
}
