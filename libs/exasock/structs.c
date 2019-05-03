#include "common.h"

#include <sys/resource.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <sched.h>

#include "lock.h"
#include "rwlock.h"
#include "structs.h"

#define RX_PKT_PREALLOC_SIZE 0x20000

struct exa_socket *exa_socket_table;
size_t exa_socket_table_size;

uint32_t exasock_tx_lock __attribute__((aligned (64)));

struct exasock_poll_sync exasock_poll_sync __attribute__((aligned (64)));

__attribute__((constructor))
void
__exasock_structs_init()
{
    struct rlimit rlim;

    if (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
    {
            fprintf(stderr, "exasock: could not get RLIMIT_NOFILE: %s\n",
                    strerror(errno));
            exit(EXIT_FAILURE);
    }

    exa_socket_table_size = rlim.rlim_max;
    exa_socket_table = calloc(exa_socket_table_size, sizeof(struct exa_socket));

    if (exa_socket_table == NULL)
    {
        fprintf(stderr, "exasock: could not allocate file descriptor table\n");
        exit(EXIT_FAILURE);
    }
}
