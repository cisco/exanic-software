#ifndef EXASOCK_WARN_H
#define EXASOCK_WARN_H

extern int __warnings_enabled;

void __exasock_warn_printf(const char *fmt, ...);

#define WARN_PRINT(...)                         \
    do {                                        \
        if (__warnings_enabled)                 \
            __exasock_warn_printf(__VA_ARGS__); \
    } while (0)

#endif /* EXASOCK_WARN_H */
