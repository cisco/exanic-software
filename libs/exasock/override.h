#ifndef EXASOCK_OVERRIDE_H
#define EXASOCK_OVERRIDE_H

/* When using the LD_PRELOAD sockets interface, temporarily turn off
 * override of certain socket functions.
 * This is needed because libexanic calls some of those functions. */
void exasock_override_off(void);
void exasock_override_on(void);
bool exasock_override_is_off(void);

ssize_t exasock_libc_read(int fd, void *buf, size_t count);

#endif /* EXASOCK_OVERRIDE_H */
