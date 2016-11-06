#include "common.h"

#include <netinet/udp.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <sched.h>

#include "lock.h"
#include "rwlock.h"
#include "structs.h"
#include "checksum.h"
#include "ip.h"
#include "udp.h"

struct exa_hashtable __exa_udp_sockfds;

__attribute__((constructor))
void
__exa_udp_init(void)
{
    exa_hashtable_init(&__exa_udp_sockfds);
}
