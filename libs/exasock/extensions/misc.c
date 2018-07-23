#include <exasock/extensions.h>
#include <stdlib.h>
#include <stdio.h>
#include "../../../include/exanic_version.h"

__attribute__((visibility("default")))
int
exasock_loaded(void)
{
    return 1;
}

__attribute__((visibility("default")))
uint32_t
exasock_version_code(void)
{
    return EXASOCK_VERSION(EXANIC_VERSION_MAJOR, EXANIC_VERSION_MINOR,
                           EXANIC_VERSION_REV);
}

__attribute__((visibility("default")))
const char *
exasock_version_text(void)
{
    return EXANIC_VERSION_TEXT;
}
