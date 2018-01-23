#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

int __warnings_enabled = 1;

__attribute__((constructor))
void
__exasock_warn_init()
{
    if (getenv("EXASOCK_NOWARN"))
        __warnings_enabled = 0;
}

void
__exasock_warn_printf(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "exasock warning: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}
