#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <assert.h>

#include "platform.h"
#include "fifo_tx.h"
#include "pcie_if.h"
#include "ioctl.h"
#include "port.h"
#include "register.h"
#include "checksum.h"

#define MAX(a,b) ((a) > (b) ? (a) : (b))

#define CACHE_ALIGN(x) (((x) + 63) & ~63)

#define FLAG_SET(x,y)    (!!((x) & (y)))

enum
{
    DEFAULT_TX_BUFFER_SIZE = 0x1000,
    FEEDBACK_INTERVAL = 512,
};

static uint32_t round_down_pow2(uint32_t n)
{
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    return (n >> 1) + 1;
}

static int exanic_alloc_tx_feedback_slot(exanic_t *exanic, int port_number)
{
    struct exanicctl_tx_feedback_alloc arg;

    arg.port_number = port_number;

    if (ioctl(exanic->fd, EXANICCTL_TX_FEEDBACK_ALLOC, &arg) != 0)
    {
        exanic_err_printf("EXANICCTL_TX_FEEDBACK_ALLOC failed: %s",
                strerror(errno));
        return -1;
    }

    return arg.feedback_slot;
}

static int exanic_free_tx_feedback_slot(exanic_t *exanic, int port_number,
                                        int feedback_slot)
{
    struct exanicctl_tx_feedback_free arg;

    arg.port_number = port_number;
    arg.feedback_slot = feedback_slot;

    if (ioctl(exanic->fd, EXANICCTL_TX_FEEDBACK_FREE, &arg) != 0)
    {
        exanic_err_printf("EXANICCTL_TX_FEEDBACK_FREE failed: %s",
                strerror(errno));
        return -1;
    }

    return 0;
}

static size_t exanic_alloc_tx_buffer(exanic_t *exanic, int port_number,
                                     size_t size)
{
    struct exanicctl_tx_buffer_alloc arg;

    arg.port_number = port_number;
    arg.size = size;

    if (ioctl(exanic->fd, EXANICCTL_TX_BUFFER_ALLOC, &arg) != 0)
    {
        exanic_err_printf("EXANICCTL_TX_BUFFER_ALLOC failed: %s",
                strerror(errno));
        return (size_t)-1;
    }

    return arg.offset;
}

static int exanic_free_tx_buffer(exanic_t *exanic, int port_number,
                                 size_t size, size_t buffer_offset)
{
    struct exanicctl_tx_buffer_free arg;

    arg.port_number = port_number;
    arg.size = size;
    arg.offset = buffer_offset;

    if (ioctl(exanic->fd, EXANICCTL_TX_BUFFER_FREE, &arg) != 0)
    {
        exanic_err_printf("EXANICCTL_TX_BUFFER_FREE failed: %s",
                strerror(errno));
        return -1;
    }

    return 0;
}

exanic_tx_t * exanic_acquire_tx_buffer(exanic_t *exanic, int port_number,
                                       size_t requested_size)
{
    size_t region_size;

    if (port_number < 0 || port_number >= exanic->num_ports)
    {
        exanic_err_printf("invalid port number");
        return NULL;
    }

    if (!exanic_port_tx_usable(exanic, port_number))
    {
        exanic_err_printf("port does not support TX");
        return NULL;
    }

    if (!exanic_port_enabled(exanic, port_number))
    {
        exanic_err_printf("port is not enabled");
        return NULL;
    }

    if (requested_size == 0)
        region_size = DEFAULT_TX_BUFFER_SIZE;
    else
        region_size = requested_size;

    if ((region_size & (PAGE_SIZE - 1)) != 0)
    {
        exanic_err_printf("TX buffer size must be a multiple of page size "
                "(%d bytes)", PAGE_SIZE);
        return NULL;
    }

    exanic_tx_t *tx = malloc(sizeof(exanic_tx_t));
    if (tx == NULL)
    {
        exanic_err_printf("Memory allocation failed for exanic_tx_t.\n");
        return NULL;
    }

    /* Request TX buffer and feedback slot allocations */
    size_t offset = exanic_alloc_tx_buffer(exanic, port_number, region_size);
    if (offset == (size_t)-1)
        goto err_alloc_buffer;

    int feedback_slot = exanic_alloc_tx_feedback_slot(exanic, port_number);
    if (feedback_slot == -1)
        goto err_feedback_slot;

    exanic_retain_handle(exanic);


    /* queue_len must be a power of 2 */
    int queue_len =
        round_down_pow2(region_size / EXANIC_TX_CMD_FIFO_SIZE_DIVISOR);
    uint32_t *feedback_offsets = calloc(queue_len, sizeof(uint32_t));
    if (feedback_offsets == NULL)
        goto err_alloc_feedback_offsets;

    tx->exanic = exanic;
    tx->port_number = port_number;
    tx->feedback_slot = feedback_slot;
    tx->feedback = &exanic->tx_feedback_slots[feedback_slot];
    tx->buffer_offset = offset;
    tx->buffer = exanic->tx_buffer + offset;
    tx->buffer_size = region_size;
    tx->next_offset = 0;
    tx->feedback_seq = 0;
    tx->request_seq = 0;
    tx->rollover_seq = 1;
    tx->next_seq = 1;
    tx->queue_len = queue_len;
    tx->feedback_offsets = feedback_offsets;
    tx->feedback_offsets[0] = region_size;

    *tx->feedback = 0;

    tx->prepared_chunk = NULL;
    tx->prepared_chunk_size = 0;

    return tx;

err_alloc_feedback_offsets:
    exanic_free_tx_feedback_slot(exanic, port_number, feedback_slot);
err_feedback_slot:
    exanic_free_tx_buffer(exanic, port_number, region_size, offset);
err_alloc_buffer:
    free(tx);
    return NULL;
}

void exanic_release_tx_buffer(exanic_tx_t *tx)
{
    if (tx == NULL)
        return;

    exanic_free_tx_buffer(tx->exanic, tx->port_number,
            tx->buffer_size, tx->buffer_offset);
    exanic_free_tx_feedback_slot(tx->exanic, tx->port_number,
            tx->feedback - tx->exanic->tx_feedback_slots);
    exanic_release_handle(tx->exanic);

    free(tx->feedback_offsets);
    free(tx);
}

static int exanic_update_tx_feedback(exanic_tx_t *tx)
{
    uint16_t feedback_seq = *tx->feedback;

    if ((uint16_t)(tx->next_seq - feedback_seq) <= tx->queue_len)
    {
        tx->feedback_seq = feedback_seq;
        return 0;
    }
    else
    {
        exanic_err_printf("invalid TX feedback sequence number 0x%lx",
                feedback_seq);
        tx->feedback_seq = tx->next_seq - 1;
        *tx->feedback = tx->feedback_seq;
        return -1;
    }
}

static size_t exanic_max_tx_chunk_size(exanic_tx_t *tx)
{
    /* The maximum TX chunk size is chosen so that we don't end up
     * waiting for a feedback that was never requested.
     *
     * Example of what we wish to avoid:
     *
     * 0. TX buffer is empty
     * 1. send chunk of size buffer_size / 2 - 8       feedback requested
     * 2. send chunk of size FEEDBACK_INTERVAL         feedback not requested
     * 3. send chunk of size buffer_size / 2           this will wait forever
     *
     * Note that the chunk size is only checked if we have to wait. */
    return tx->buffer_size / 2 - FEEDBACK_INTERVAL;
}

static struct tx_chunk * exanic_prepare_tx_chunk(exanic_tx_t *tx,
                                                 size_t chunk_size)
{
    size_t aligned_size = CACHE_ALIGN(chunk_size);
    size_t request_offset =
        tx->feedback_offsets[tx->request_seq & (tx->queue_len - 1)];

    while ((uint16_t)(tx->next_seq - tx->feedback_seq) >= tx->queue_len)
    {
        /* Spin on TX feedback for more available sequence numbers */
        if (exanic_update_tx_feedback(tx) == -1)
            return NULL;
    }

    while (1)
    {
        /* Check if we have not wrapped around since feedback_seq */
        if ((uint16_t)(tx->next_seq - tx->feedback_seq) <=
                (uint16_t)(tx->next_seq - tx->rollover_seq))
        {
            /* Everything after next_offset is available */
            if (tx->next_offset + aligned_size <= tx->buffer_size)
                break;

            /* Not enough space, need to wrap around */
            tx->next_offset = 0;
            tx->rollover_seq = tx->next_seq;
        }

        /* Available space is between next_offset and feedback_offset */
        size_t feedback_offset =
            tx->feedback_offsets[tx->feedback_seq & (tx->queue_len - 1)];
        if (tx->next_offset + aligned_size <= feedback_offset)
            break;

        /* Make sure chunk size is not too big so that we don't wait forever */
        if (aligned_size > exanic_max_tx_chunk_size(tx))
        {
            exanic_err_printf("requested TX chunk size is too large");
            return NULL;
        }

        /* Spin on TX feedback for more space */
        if (exanic_update_tx_feedback(tx) == -1)
            return NULL;
    }

    /* We request feedback if the last request was too long ago, by sequence
     * number or by amount of data sent */
    if ((uint16_t)(tx->next_seq - tx->request_seq) > tx->queue_len / 2)
        /* Need more sequence numbers */
        tx->need_feedback = 1;
    else if ((uint16_t)(tx->next_seq - tx->request_seq) >
            (uint16_t)(tx->next_seq - tx->rollover_seq))
        /* Wrapped around since last feedback request */
        tx->need_feedback = 1;
    else if (tx->next_offset + aligned_size - request_offset >
             FEEDBACK_INTERVAL)
        /* Too many bytes since last feedback request */
        tx->need_feedback = 1;
    else
        tx->need_feedback = 0;

    return (struct tx_chunk *)(tx->buffer + tx->next_offset);
}

/*
 * attempt to write pcie version registers [RO]
 * to wake up pcie hardware without side effect
 */
static void exanic_dummy_reg_write(exanic_tx_t *tx)
{
    tx->exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_PCIE_IF_VER)] =
        0xdeadbeef;
}

static void exanic_send_tx_chunk(exanic_tx_t *tx, size_t chunk_size)
{
    size_t aligned_size = CACHE_ALIGN(chunk_size);
    struct tx_chunk *chunk = (struct tx_chunk *)(tx->buffer + tx->next_offset);
    size_t offset = tx->next_offset;

    tx->next_offset += aligned_size;

    /* Fill out feedback info in tx_chunk header */
    chunk->feedback_id = tx->next_seq;
    chunk->feedback_slot_index = tx->feedback_slot |
        (tx->need_feedback ? 0 : 0x8000);

    /* Send transmit command */
    iowb();
    tx->exanic->registers[REG_PORT_INDEX(tx->port_number, REG_PORT_TX_COMMAND)]
        = offset + tx->buffer_offset;

    /* Update state */
    tx->feedback_offsets[tx->next_seq & (tx->queue_len - 1)]
        = tx->next_offset;
    if (tx->need_feedback)
        tx->request_seq = tx->next_seq;
    tx->next_seq++;
}

size_t exanic_get_tx_mtu(exanic_tx_t *tx)
{
    size_t padding = exanic_payload_padding_bytes(EXANIC_TX_TYPE_RAW);
    size_t max_chunk_size = exanic_max_tx_chunk_size(tx);

    return max_chunk_size - padding - sizeof(struct tx_chunk);
}

static inline int __attribute__((always_inline))
exanic_transmit_frame_common(exanic_tx_t *tx, const char *frame,
                             size_t frame_size, uint32_t flags)
{
    size_t padding = exanic_payload_padding_bytes(EXANIC_TX_TYPE_RAW);
    size_t chunk_size = frame_size + padding + sizeof(struct tx_chunk);
    struct tx_chunk *chunk;
    long warm = FLAG_SET(flags, EXA_FRAME_WARM) ? 1 : 0;

    if (tx->prepared_chunk != NULL)
    {
        exanic_err_printf("missing call to exanic_end_transmit_*");
        return -1;
    }

    chunk = exanic_prepare_tx_chunk(tx, chunk_size);
    if (chunk == NULL)
        return -1;

    if (__builtin_expect(warm, 0))
    {
        exanic_dummy_reg_write(tx);
        return 0;
    }

    /*
     * code below is skipped when the warm flag is set
     * it can make performance worse when the frame
     * is large
     */
    chunk->length = frame_size + padding;
    chunk->type = EXANIC_TX_TYPE_RAW;
    chunk->flags = 0;
    /* write padding to avoid a gap in the write-combining buffer */
    memset(chunk->payload, 0, padding);
    memcpy(chunk->payload + padding, frame, frame_size);
    exanic_send_tx_chunk(tx, chunk_size);
    return 0;
}

int exanic_transmit_frame_ex(exanic_tx_t *tx, const char *frame,
                             size_t frame_size, uint32_t flags)
{
    return exanic_transmit_frame_common(tx, frame, frame_size, flags);
}

int exanic_transmit_frame(exanic_tx_t *tx, const char *frame,
                          size_t frame_size)
{
    return exanic_transmit_frame_common(tx, frame, frame_size, 0);
}

char * exanic_begin_transmit_frame(exanic_tx_t *tx, size_t frame_size)
{
    size_t padding = exanic_payload_padding_bytes(EXANIC_TX_TYPE_RAW);
    size_t length = padding + frame_size;
    size_t chunk_size = sizeof(struct tx_chunk) + length;

    if (tx->prepared_chunk != NULL)
    {
        exanic_err_printf("missing call to exanic_end_transmit_*");
        return NULL;
    }

    tx->prepared_chunk = exanic_prepare_tx_chunk(tx, chunk_size);
    if (tx->prepared_chunk == NULL)
        return NULL;

    tx->prepared_chunk_size = chunk_size;

    tx->prepared_chunk->length = length;
    tx->prepared_chunk->type = EXANIC_TX_TYPE_RAW;
    tx->prepared_chunk->flags = 0;
    /* write padding to avoid a gap in the write-combining buffer */
    memset(tx->prepared_chunk->payload, 0, padding);

    return tx->prepared_chunk->payload + padding;
}

int exanic_end_transmit_frame(exanic_tx_t *tx, size_t frame_size)
{
    size_t chunk_size;

    if (frame_size != 0)
    {
        size_t padding = exanic_payload_padding_bytes(EXANIC_TX_TYPE_RAW);
        size_t length = padding + frame_size;
        chunk_size = sizeof(struct tx_chunk) + length;
        tx->prepared_chunk->length = length;
    }
    else
        chunk_size = tx->prepared_chunk_size;

    exanic_send_tx_chunk(tx, chunk_size);
    tx->prepared_chunk = NULL;

    return 0;
}

int exanic_transmit_payload(exanic_tx_t *tx, uint16_t connection_id,
                            exanic_tx_type_id_t type, const char* payload,
                            size_t payload_size)
{
    size_t padding = exanic_payload_padding_bytes(type);
    size_t length = padding + sizeof(struct tx_payload_metadata) + payload_size;
    size_t chunk_size = sizeof(struct tx_chunk) + length;
    struct tx_payload_metadata payload_metadata;
    struct tx_chunk *chunk;
    char *payload_ptr;

    if (tx->prepared_chunk != NULL)
    {
        exanic_err_printf("missing call to exanic_end_transmit_*");
        return -1;
    }

    chunk = exanic_prepare_tx_chunk(tx, chunk_size);
    if (chunk == NULL)
        return -1;

    chunk->length = length;
    chunk->type = type;
    chunk->flags = 0;

    payload_metadata.csum = htons(csum(payload, payload_size, 0));

    payload_metadata.connection_id = connection_id;
    payload_ptr = chunk->payload + padding;
    memcpy(payload_ptr, &payload_metadata, sizeof(struct tx_payload_metadata));

    payload_ptr += sizeof(struct tx_payload_metadata);
    memcpy(payload_ptr, payload, payload_size);

    exanic_send_tx_chunk(tx, chunk_size);

    return 0;
}

char * exanic_begin_transmit_payload(exanic_tx_t *tx, uint16_t connection_id,
                                     exanic_tx_type_id_t type,
                                     size_t payload_size, uint16_t **csum)
{
    size_t padding = exanic_payload_padding_bytes(type);
    size_t length = padding + sizeof(struct tx_payload_metadata) + payload_size;
    size_t chunk_size = sizeof(struct tx_chunk) + length;
    struct tx_payload_metadata *ate_hdr;

    if (tx->prepared_chunk != NULL)
    {
        exanic_err_printf("missing call to exanic_end_transmit_*");
        return NULL;
    }

    tx->prepared_chunk = exanic_prepare_tx_chunk(tx, chunk_size);
    if (tx->prepared_chunk == NULL)
        return NULL;

    tx->prepared_chunk_size = chunk_size;

    tx->prepared_chunk->length = length;
    tx->prepared_chunk->type = type;
    tx->prepared_chunk->flags = 0;

    ate_hdr = (struct tx_payload_metadata *)(tx->prepared_chunk->payload + padding);
    assert((intptr_t)ate_hdr % __alignof__(*ate_hdr) == 0);

    *csum = &ate_hdr->csum;
    ate_hdr->connection_id = connection_id;

    return (char *)&ate_hdr->payload;
}

int exanic_end_transmit_payload(exanic_tx_t* tx, exanic_tx_type_id_t type,
                                size_t payload_size)
{
    size_t chunk_size;

    if (payload_size != 0)
    {
        size_t padding = exanic_payload_padding_bytes(type);
        size_t length = padding + sizeof(struct tx_payload_metadata) + payload_size;
        chunk_size = sizeof(struct tx_chunk) + length;
        tx->prepared_chunk->length = length;
    }
    else
        chunk_size = tx->prepared_chunk_size;

    exanic_send_tx_chunk(tx, chunk_size);
    tx->prepared_chunk = NULL;

    return 0;
}

int exanic_abort_transmit_frame(exanic_tx_t *tx)
{
    tx->prepared_chunk = NULL;

    return 0;
}

exanic_cycles32_t exanic_get_tx_timestamp(exanic_tx_t *tx)
{
    return exanic_register_read(tx->exanic,
            REG_PORT_INDEX(tx->port_number, REG_PORT_TX_LAST_TIME));
}
