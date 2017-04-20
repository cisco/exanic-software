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

    rx->exanic = exanic;
    rx->port_number = port_number;
    rx->buffer = rx_buffer;
    rx->buffer_number = buffer_number;

    __exanic_rx_catchup(rx);
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

    rx->exanic = exanic;
    rx->port_number = port_number;
    rx->buffer = rx_buffer;
    rx->buffer_number = arg.buffer_number + 1;

    __exanic_rx_catchup(rx);
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
    /* Find the next chunk in which data will arrive */
    uint8_t generation = rx->buffer[0].u.info.generation;
    uint32_t next_chunk;
    for (next_chunk = 1; next_chunk < EXANIC_RX_NUM_CHUNKS; next_chunk++)
        if (rx->buffer[next_chunk].u.info.generation != generation)
            break;
    if (next_chunk < EXANIC_RX_NUM_CHUNKS)
    {
        rx->generation = generation;
        rx->next_chunk = next_chunk;
    }
    else
    {
        rx->generation = generation + 1;
        rx->next_chunk = 0;
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
                size += u.info.length;

                /* TODO: Recheck that we haven't been lapped */

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

            /* TODO: Recheck that we haven't been lapped */

            if (u.info.frame_status & EXANIC_RX_FRAME_ERROR_MASK)
                return -(u.info.frame_status & EXANIC_RX_FRAME_ERROR_MASK);

            *more_chunks = 0;
            return u.info.length;
        }
        else
        {
            /* More chunks to come */
            memcpy(rx_buf, payload, EXANIC_RX_CHUNK_PAYLOAD_SIZE);

            *more_chunks = 1;
            return EXANIC_RX_CHUNK_PAYLOAD_SIZE;
        }
    }
    else if (u.info.generation == (uint8_t)(rx->generation - 1))
    {
        /* No new data */
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
        /* TODO: Recheck that we haven't been lapped */
        *more_chunks = more;
        *info = u.info;
        return length;
    }
    else if (u.info.generation == (uint8_t)(rx->generation - 1))
    {
        /* No new data */
        return 0;
    }
    else
    {
        /* Got lapped? */
        __exanic_rx_catchup(rx);
        return -EXANIC_RX_FRAME_SWOVFL;
    }
}
