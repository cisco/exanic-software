#ifndef EXASOCK_WARN_H
#define EXASOCK_WARN_H

extern int __warnings_enabled;

void __exasock_warn_printf(const char *fmt, ...);

#define __WARN_PRINT(...)                       \
    do {                                        \
        if (__warnings_enabled)                 \
            __exasock_warn_printf(__VA_ARGS__); \
    } while (0)

#define WARNING_MCAST(fd) \
    __WARN_PRINT("listening to multicast data on not accelerated socket (fd=%i)", \
                 (fd))
#define WARNING_MSGWARM(fd) \
    __WARN_PRINT("sending MSG_EXA_WARM message on not accelerated socket (fd=%i) - skipped", \
                 (fd))
#define WARNING_SOCKOPT(so) \
    __WARN_PRINT("setting of %s on accelerated socket is not effective", \
                 (so))

#endif /* EXASOCK_WARN_H */
