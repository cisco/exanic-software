#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <limits.h>

#include "fifo_rx.h"
#include "pcie_if.h"
#include "port.h"
#include "ioctl.h"
#include "util.h"

exanic_rx_t * exanic_acquire_rx_buffer(exanic_t *exanic, int port_number,
                                       int buffer_number)
{
    unsigned int page_offset;
    if (port_number < 0 || port_number >= exanic->num_ports)
    {
        exanic_err_printf("invalid port number");
        return NULL;
    }

    if (!exanic_port_rx_usable(exanic, port_number))
    {
        exanic_err_printf("port does not support RX");
        return NULL;
    }

    if (!exanic_port_enabled(exanic, port_number))
    {
        exanic_err_printf("port is not enabled");
        return NULL;
    }

    if (buffer_number > 0)
    {
        /* Need to allocate the buffer if it isn't already. */
        struct exanicctl_rx_filter_buffer_alloc arg;
        arg.port_number = port_number;
        arg.buffer_number = buffer_number - 1;
        if (ioctl(exanic->fd, EXANICCTL_RX_FILTER_BUFFER_ALLOC_EX,
                  &arg) != 0)
        {
            exanic_err_printf("EXANICCTL_RX_FILTER_BUFFER_ALLOC_EX failed: %s",
                    strerror(errno));
            return NULL;
        }

        page_offset = EXANIC_PGOFF_FILTER_REGION * PAGE_SIZE
                      + (port_number * exanic->max_filter_buffers
                          * EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE)
                      + ((buffer_number-1) * EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE);
    }
    else
    {
        if (port_number < 4)
            page_offset = EXANIC_PGOFF_RX_REGION * PAGE_SIZE
                          + port_number * EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE;
        else
            page_offset = EXANIC_PGOFF_RX_REGION_EXT * PAGE_SIZE
                          + port_number * EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE;

    }

    struct rx_chunk *rx_buffer = mmap(NULL, EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE,
            PROT_READ, MAP_SHARED, exanic->fd, page_offset);
    if (rx_buffer == MAP_FAILED)
    {
        exanic_err_printf("rx mmap failed: %s", strerror(errno));
        return NULL;
    }

    exanic_retain_handle(exanic);

    exanic_rx_t *rx = malloc(sizeof(exanic_rx_t));
    if (rx != NULL)
    {
       rx->exanic = exanic;
       rx->port_number = port_number;
       rx->buffer = rx_buffer;
       rx->buffer_number = buffer_number;

       __exanic_rx_catchup(rx);
    }
    return rx;
}

exanic_rx_t * exanic_acquire_unused_filter_buffer(exanic_t *exanic,
                                                int port_number)
{
    int page_offset;
    if (port_number < 0 || port_number >= exanic->num_ports)
    {
        exanic_err_printf("invalid port number");
        return NULL;
    }

    if (!exanic_port_rx_usable(exanic, port_number))
    {
        exanic_err_printf("port does not support RX");
        return NULL;
    }

    if (!exanic_port_enabled(exanic, port_number))
    {
        exanic_err_printf("port is not enabled");
        return NULL;
    }

    struct exanicctl_rx_filter_buffer_alloc arg;
    arg.port_number = port_number;
    arg.buffer_number = UINT_MAX;
    if (ioctl(exanic->fd, EXANICCTL_RX_FILTER_BUFFER_ALLOC_EX,
              &arg) != 0)
    {
        exanic_err_printf("EXANICCTL_RX_FILTER_BUFFER_ALLOC_EX failed: %s",
                strerror(errno));
        return NULL;
    }

    page_offset = EXANIC_PGOFF_FILTER_REGION * PAGE_SIZE
                  + (port_number * exanic->max_filter_buffers
                      * EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE)
                  + ((arg.buffer_number) * EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE);

    struct rx_chunk *rx_buffer = mmap(NULL, EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE,
            PROT_READ, MAP_SHARED, exanic->fd, page_offset);
    if (rx_buffer == MAP_FAILED)
    {
        exanic_err_printf("rx mmap failed: %s", strerror(errno));
        return NULL;
    }

    exanic_retain_handle(exanic);

    exanic_rx_t *rx = malloc(sizeof(exanic_rx_t));
    if( rx != NULL) {
        rx->exanic = exanic;
        rx->port_number = port_number;
        rx->buffer = rx_buffer;
        rx->buffer_number = arg.buffer_number + 1;

        __exanic_rx_catchup(rx);
    }

    return rx;
}

int exanic_enable_flow_hashing(exanic_t *exanic, int port_number,
                                int max_buffers, int hash_function)
{
    int num_buffers;

    if ((max_buffers != 1) && (max_buffers & (max_buffers - 1)))
    {
        exanic_err_printf("max buffers must be a power of 2");
        return -1;
    }

    if (port_number < 0 || port_number >= exanic->num_ports)
    {
        exanic_err_printf("invalid port number");
        return -1;
    }

    if (!exanic_port_rx_usable(exanic, port_number))
    {
        exanic_err_printf("port does not support RX");
        return -1;
    }

    if (!exanic_port_enabled(exanic, port_number))
    {
        exanic_err_printf("port is not enabled");
        return -1;
    }

    /* Attempt to allocate all requested buffers. */
    for (num_buffers = 0; num_buffers < max_buffers; num_buffers++)
    {
        struct exanicctl_rx_filter_buffer_alloc arg;
        arg.port_number = port_number;
        arg.buffer_number = num_buffers;
        if (ioctl(exanic->fd, EXANICCTL_RX_FILTER_BUFFER_ALLOC_EX,
                  &arg) != 0)
            break;
    }

    if (num_buffers == 0)
    {
        exanic_err_printf("couldn't allocate any buffers");
        return -1;
    }

    /* Need to roll back to the nearest pow2 */
    while ((num_buffers != 1) && (num_buffers & (num_buffers - 1)))
    {
        struct exanicctl_rx_filter_buffer_free arg;
        arg.port_number = port_number;
        arg.buffer_number = num_buffers - 1;
        ioctl(exanic->fd, EXANICCTL_RX_FILTER_BUFFER_FREE, &arg);
        num_buffers--;
    }

    /* Now we can enable flow hashing. */
    {
        struct exanicctl_rx_hash_configure arg;
        arg.port_number = port_number;
        arg.enable = 1;
        arg.mask = num_buffers - 1;
        arg.function = hash_function;
        ioctl(exanic->fd, EXANICCTL_RX_HASH_CONFIGURE, &arg);
    }

    return num_buffers;
}

void exanic_disable_flow_hashing(exanic_t *exanic, int port_number)
{
    struct exanicctl_rx_hash_configure arg;

    arg.port_number = port_number;
    arg.enable = 0;
    arg.mask = 0;
    arg.function = 0;

    ioctl(exanic->fd, EXANICCTL_RX_HASH_CONFIGURE, &arg);
}

void exanic_release_rx_buffer(exanic_rx_t *rx)
{
    if (rx == NULL)
        return;

    munmap((void *)rx->buffer, EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE);

    if (rx->buffer_number > 0)
    {
        struct exanicctl_rx_filter_buffer_free arg;
        arg.port_number = rx->port_number;
        arg.buffer_number = rx->buffer_number-1;
        ioctl(rx->exanic->fd, EXANICCTL_RX_FILTER_BUFFER_FREE,
              &arg);
    }

    exanic_release_handle(rx->exanic);

    free(rx);
}

void __exanic_rx_catchup(exanic_rx_t *rx)
{
    /* Find the most recent end-of-frame chunk in the RX region,
     * and move next_chunk pointer to the next chunk after it
     *
     * If no end-of-frame or uninitialized chunks are encountered
     * (shouldn't happen), then move next_chunk pointer to where
     * the generation number changes */
    uint8_t eof_gen = 0, break_gen = 0;
    uint32_t eof_chunk = 0, break_chunk = 0, chunk;
    bool eof_found = false, before_break = false;
    union {
        struct rx_chunk_info info;
        uint64_t data;
    } u;

    /* Iterate backwards through RX region */
    for (chunk = EXANIC_RX_NUM_CHUNKS; chunk-- > 0; )
    {
        u.data = rx->buffer[chunk].u.data;

        if (chunk == EXANIC_RX_NUM_CHUNKS - 1)
        {
            /* Starting value assumes break is at the wrap-around */
            break_gen = u.info.generation;
            break_chunk = EXANIC_RX_NUM_CHUNKS - 1;
        }
        else if (u.info.generation != break_gen)
        {
            /* Found break in generation number */
            before_break = true;
            break_gen = u.info.generation;
            break_chunk = chunk;
        }

        /* Length field is non-zero for both end-of-frame chunks and
         * uninitialized chunks */
        if (u.info.length != 0)
        {
            if (before_break)
            {
                /* Found an end-of-frame before the break
                 * This is the most recent end-of-frame */
                eof_found = true;
                eof_gen = u.info.generation;
                eof_chunk = chunk;
                break;
            }
            else if (!eof_found)
            {
                /* Found the final end-of-frame before the wrap-around
                 * If there are no end-of-frames before the break, then
                 * this is the most recent end-of-frame */
                eof_found = true;
                eof_gen = u.info.generation;
                eof_chunk = chunk;
            }
        }
    }

    if (eof_found)
    {
        /* Set next_chunk to the chunk after the most recent end-of-frame */
        rx->sentinel_chunk = eof_chunk;
        rx->sentinel_chunk_generation = eof_gen;
        rx->next_chunk = eof_chunk + 1;
        rx->generation = eof_gen;
    }
    else
    {
        /* Set next_chunk to where generation number changes */
        rx->sentinel_chunk = break_chunk;
        rx->sentinel_chunk_generation = break_gen;
        rx->next_chunk = break_chunk + 1;
        rx->generation = break_gen;
    }

    if (rx->next_chunk == EXANIC_RX_NUM_CHUNKS)
    {
        rx->next_chunk = 0;
        rx->generation++;
    }
}

ssize_t exanic_receive_frame(exanic_rx_t *rx, char *rx_buf, size_t rx_buf_size,
                             exanic_cycles32_t *timestamp)
{
    union {
        struct rx_chunk_info info;
        uint64_t data;
    } u;

    u.data = rx->buffer[rx->next_chunk].u.data;

    if (u.info.generation == rx->generation)
    {
        size_t size = 0;

        /* Next expected packet */
        while (1)
        {
            uint32_t current_chunk = rx->next_chunk;
            const char *payload = (char *)rx->buffer[rx->next_chunk].payload;

            /* Advance next_chunk to next chunk */
            rx->next_chunk++;
            if (rx->next_chunk == EXANIC_RX_NUM_CHUNKS)
            {
                rx->next_chunk = 0;
                rx->generation++;
            }

            /* Process current chunk */
            if (u.info.length != 0)
            {
                /* Last chunk */
                if (size + u.info.length > rx_buf_size)
                    return -EXANIC_RX_FRAME_TRUNCATED;

                memcpy(rx_buf + size, payload, u.info.length);

                /* Move the sentinel chunk forward. */
                uint32_t sentinel_chunk = rx->sentinel_chunk;
                uint8_t sentinel_chunk_generation = rx->sentinel_chunk_generation;
                rx->sentinel_chunk = current_chunk;
                rx->sentinel_chunk_generation = u.info.generation;

                /* Check that we couldn't have gotten lapped during memcpy. */
                if (rx->buffer[sentinel_chunk].u.info.generation !=
                      sentinel_chunk_generation)
                {
                    __exanic_rx_catchup(rx);
                    return -EXANIC_RX_FRAME_SWOVFL;
                }

                size += u.info.length;

                if (timestamp != NULL)
                    *timestamp = u.info.timestamp;

                if (u.info.frame_status & EXANIC_RX_FRAME_ERROR_MASK)
                    return -(u.info.frame_status & EXANIC_RX_FRAME_ERROR_MASK);

                return size;
            }
            else
            {
                /* More chunks to come */
                if (size + EXANIC_RX_CHUNK_PAYLOAD_SIZE <= rx_buf_size)
                    memcpy(rx_buf + size, payload,
                            EXANIC_RX_CHUNK_PAYLOAD_SIZE);
                size += EXANIC_RX_CHUNK_PAYLOAD_SIZE;

                /* Spin on next chunk */
                do
                    u.data = rx->buffer[rx->next_chunk].u.data;
                while (u.info.generation == (uint8_t)(rx->generation - 1));

                if (u.info.generation != rx->generation)
                {
                    /* Got lapped? */
                    __exanic_rx_catchup(rx);
                    return -EXANIC_RX_FRAME_SWOVFL;
                }
            }
        }
    }
    else if (u.info.generation == (uint8_t)(rx->generation - 1))
    {
        /* No new packet */
        __builtin_prefetch((const void*)&rx->buffer[rx->sentinel_chunk].u.info.generation, 0, 3);
        return 0;
    }
    else
    {
        /* Got lapped? */
        __exanic_rx_catchup(rx);
        return -EXANIC_RX_FRAME_SWOVFL;
    }
}

ssize_t exanic_receive_chunk(exanic_rx_t *rx, char *rx_buf, int *more_chunks)
{
    union {
        struct rx_chunk_info info;
        uint64_t data;
    } u;

    u.data = rx->buffer[rx->next_chunk].u.data;

    if (u.info.generation == rx->generation)
    {
        /* Data is available */
        const char *payload = (char *)rx->buffer[rx->next_chunk].payload;
        uint32_t sentinel_chunk = rx->sentinel_chunk;
        uint8_t sentinel_chunk_generation = rx->sentinel_chunk_generation;

        /* Move the sentinel chunk forward. */
        rx->sentinel_chunk = rx->next_chunk;
        rx->sentinel_chunk_generation = u.info.generation;

        /* Advance next_chunk to next chunk */
        rx->next_chunk++;
        if (rx->next_chunk == EXANIC_RX_NUM_CHUNKS)
        {
            rx->next_chunk = 0;
            rx->generation++;
        }

        if (u.info.length != 0)
        {
            /* Last chunk */
            memcpy(rx_buf, payload, u.info.length);

            /* Check that memory of the prev chunk was not overwritten by hardware */
            if (rx->buffer[sentinel_chunk].u.info.generation != sentinel_chunk_generation)
            {
                __exanic_rx_catchup(rx);
                return -EXANIC_RX_FRAME_SWOVFL;
            }

            if (u.info.frame_status & EXANIC_RX_FRAME_ERROR_MASK)
                return -(u.info.frame_status & EXANIC_RX_FRAME_ERROR_MASK);

            *more_chunks = 0;
            return u.info.length;
        }
        else
        {
            /* More chunks to come */
            memcpy(rx_buf, payload, EXANIC_RX_CHUNK_PAYLOAD_SIZE);

            /* Check memory of the prev chunk was not overwritten by hardware */
            if (rx->buffer[sentinel_chunk].u.info.generation != sentinel_chunk_generation)
            {
                __exanic_rx_catchup(rx);
                return -EXANIC_RX_FRAME_SWOVFL;
            }

            *more_chunks = 1;
            return EXANIC_RX_CHUNK_PAYLOAD_SIZE;
        }
    }
    else if (u.info.generation == (uint8_t)(rx->generation - 1))
    {
        /* No new data */
        __builtin_prefetch((const void*)&rx->buffer[rx->sentinel_chunk].u.info.generation, 0, 3);
        return 0;
    }
    else
    {
        /* Got lapped? */
        __exanic_rx_catchup(rx);
        return -EXANIC_RX_FRAME_SWOVFL;
    }
}

ssize_t exanic_receive_chunk_ex(exanic_rx_t *rx, char *rx_buf, int *more_chunks,
     struct rx_chunk_info *info)
{
    union {
        struct rx_chunk_info info;
        uint64_t data;
    } u;

    u.data = rx->buffer[rx->next_chunk].u.data;

    if (u.info.generation == rx->generation)
    {
        /* Data is available */
        const char *payload = (char *)rx->buffer[rx->next_chunk].payload;
        uint8_t length;
        int more;
        uint32_t sentinel_chunk = rx->sentinel_chunk;
        uint8_t sentinel_chunk_generation = rx->sentinel_chunk_generation;

        /* Move the sentinel chunk forward. */
        rx->sentinel_chunk = rx->next_chunk;
        rx->sentinel_chunk_generation = u.info.generation;

        /* Advance next_chunk to next chunk */
        rx->next_chunk++;
        if (rx->next_chunk == EXANIC_RX_NUM_CHUNKS)
        {
            rx->next_chunk = 0;
            rx->generation++;
        }
        more = (u.info.length == 0);
        length = more ? EXANIC_RX_CHUNK_PAYLOAD_SIZE : u.info.length;
        memcpy(rx_buf, payload, length);

        /* Check that the memory of the prev chunk was not overwritten by hardware */
        if (rx->buffer[sentinel_chunk].u.info.generation != sentinel_chunk_generation)
        {
            __exanic_rx_catchup(rx);
            return -EXANIC_RX_FRAME_SWOVFL;
        }

        *more_chunks = more;
        *info = u.info;
        return length;
    }
    else if (u.info.generation == (uint8_t)(rx->generation - 1))
    {
        /* No new data */
        __builtin_prefetch((const void*)&rx->buffer[rx->sentinel_chunk].u.info.generation, 0, 3);
        return 0;
    }
    else
    {
        /* Got lapped? */
        __exanic_rx_catchup(rx);
        return -EXANIC_RX_FRAME_SWOVFL;
    }
}
