/**
 * \file
 * \brief Functions for receiving data on ExaNICs.
 */
#ifndef EXANIC_FIFO_RX_H
#define EXANIC_FIFO_RX_H

#include <unistd.h> /* for ssize_t */

#include "exanic.h"
#include "pcie_if.h"
#include "fifo_if.h"
#include "time.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Additional status codes for received frames.
 *
 * See \ref rx_frame_status for hardware status codes.
 */
enum rx_frame_status_sw_err
{
    /** One or more frames were lost due to software overflow (check CPU contention). */
    EXANIC_RX_FRAME_SWOVFL      = 256,

    /** Provided buffer was too small. */
    EXANIC_RX_FRAME_TRUNCATED   = 257,
};

/**
 * \brief A handle to a ExaNIC RX FIFO
 */
typedef struct exanic_rx
{
    exanic_t    *exanic;
    int         port_number;
    int         buffer_number;
    volatile    struct rx_chunk *buffer;
    uint32_t    next_chunk;
    uint8_t     generation;
    uint32_t    sentinel_chunk;
    uint32_t    sentinel_chunk_generation;
} exanic_rx_t;

/**
 * \brief Acquire access to a ExaNIC RX buffer
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle.
 * \param[in]   port_number
 *      The port number.
 * \param[in]   buffer_number
 *      The buffer to obtain. Buffer 0 is the default ExaNIC buffer, buffers > 0
 *      are used in flow steering and flow hashing applications.
 *
 * \return A handle to the RX buffer.
 */
exanic_rx_t * exanic_acquire_rx_buffer(exanic_t *exanic, int port_number,
                                       int buffer_number);

/**
 * \brief Allocate and return an unused RX filter buffer for flow steering.
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle.
 * \param[in]   port_number
 *      The port number.
 *
 * \return A handle to the RX buffer.
 */
exanic_rx_t * exanic_acquire_unused_filter_buffer(exanic_t *exanic,
                                                int port_number);

/**
 * \brief Free an ExaNIC RX buffer
 *
 * \param[in]   rx
 *      A valid RX handle.
 */
void exanic_release_rx_buffer(exanic_rx_t *rx);

/**
 * \brief Enable flow hashing on an ExaNIC port.
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle.
 * \param[in]   port_number
 *      The port number.
 * \param[in]   max_buffers
 *      The maximum number of RX buffers to allocate (must be a power of 2).
 *
 *
 * \return The number of RX buffers actually allocated.
 */
int exanic_enable_flow_hashing(exanic_t *exanic, int port_number,
                                int max_buffers, int hash_function);

/**
 * \brief Disable flow hashing on an ExaNIC port.
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle.
 * \param[in]   port_number
 *      The port number.
 *
 */
void exanic_disable_flow_hashing(exanic_t *exanic, int port_number);



void __exanic_rx_catchup(exanic_rx_t *rx);

/**
 * \brief Read a frame into the provided buffer
 *
 * \param[in]   rx
 *      A valid RX handle.
 * \param[out]  rx_buf
 *      Pointer to the user provided buffer.
 * \param[in]   rx_buf_size
 *      Size of the user provided buffer.
 * \param[out]  timestamp
 *
 * \return Size of the frame, or 0 if no frame is available,
 *         or <0 for errors (see \ref rx_frame_status).
 */
ssize_t exanic_receive_frame(exanic_rx_t *rx, char *rx_buf, size_t rx_buf_size,
                             exanic_cycles32_t *timestamp);

/**
 * \brief Read one chunk of data into the provided buffer
 *
 * \param[in]   rx
 *      A valid RX handle.
 * \param[out]  rx_buf
 *      Pointer to the user provided buffer.
 *      Must have at least \ref EXANIC_RX_CHUNK_PAYLOAD_SIZE bytes of space.
 * \param[out]  more_chunks
 *      Set to non-zero if there are more chunks in the current frame,
 *      or zero if it is the last chunk. Left unchanged if no data was read.
 *
 * \return Size of the chunk, or 0 if no data available,
 *         or <0 for errors (see \ref rx_frame_status).
 */
ssize_t exanic_receive_chunk(exanic_rx_t *rx, char *rx_buf, int *more_chunks);

/**
 * \brief Provide a pointer to the next chunk in the RX buffer
 *
 * \param[in]   rx
 *      A valid RX handle.
 * \param[out]  rx_buf_ptr
 *      Pointer which will be populated with the address of the next chunk
 *      in the ExaNIC RX buffer.
 * \param[out]  chunkid
 *      Set to a number which identifies the chunk.  This can be passed to
 *      \ref exanic_receive_chunk_valid() after processing to check if the chunk
 *      has been overwritten.
 * \param[out]  more_chunks
 *      Set to non-zero if there are more chunks in the current frame,
 *      or zero if it is the last chunk.  Left unchanged if no new chunk found.
 *
 * \return Size of the chunk, or 0 if no data available,
 *         or <0 for errors (see \ref rx_frame_status).
 */
static inline ssize_t exanic_receive_chunk_inplace(exanic_rx_t *rx,
                                                   char **rx_buf_ptr,
                                                   uint32_t *chunk_id,
                                                   int *more_chunks)
{
    union {
        struct rx_chunk_info info;
        uint64_t data;
    } u;

    u.data = rx->buffer[rx->next_chunk].u.data;

    if (u.info.generation == rx->generation)
    {
        /* Data is available */
        *rx_buf_ptr = (char *)rx->buffer[rx->next_chunk].payload;

        if (chunk_id != NULL)
            *chunk_id = rx->generation * EXANIC_RX_NUM_CHUNKS + rx->next_chunk;

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
            if (u.info.frame_status & EXANIC_RX_FRAME_ERROR_MASK)
                return -(u.info.frame_status & EXANIC_RX_FRAME_ERROR_MASK);

            *more_chunks = 0;
            return u.info.length;
        }
        else
        {
            /* More chunks to come */
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


/**
 * \brief Provide a pointer to the next chunk in the RX buffer, returning
 * metadata about the chunk
 *
 * \param[in]   rx
 *      A valid RX handle.
 * \param[out]  rx_buf_ptr
 *      Pointer which will be populated with the address of the next chunk
 *      in the ExaNIC RX buffer.
 * \param[out]  chunkid
 *      Set to a number which identifies the chunk.  This can be passed to
 *      \ref exanic_receive_chunk_valid() after processing to check if the chunk
 *      has been overwritten.
 * \param[out]  more_chunks
 *      Set to non-zero if there are more chunks in the current frame,
 *      or zero if it is the last chunk.  Left unchanged if no new chunk found.
 * \param[out]  info
 *      Returns a copy of the chunk metadata from the hardware.
 *
 * This function will return chunk data even if the frame has errors.  The
 * caller should check info.frame_status for errors (see \ref rx_frame_status).
 *
 * \return Size of the chunk, or 0 if no data available,
 *         or -EXANIC_RX_FRAME_SWOVFL if chunks were missed by software.
 *
 */
static inline ssize_t exanic_receive_chunk_inplace_ex(exanic_rx_t *rx,
                                                   char **rx_buf_ptr,
                                                   uint32_t *chunk_id,
                                                   int *more_chunks,
                                                   struct rx_chunk_info *info)
{
    union {
        struct rx_chunk_info info;
        uint64_t data;
    } u;

    ssize_t length = 0;

    u.data = rx->buffer[rx->next_chunk].u.data;

    if (u.info.generation == rx->generation)
    {
        /* Data is available */
        *rx_buf_ptr = (char *)rx->buffer[rx->next_chunk].payload;

        if (chunk_id != NULL)
            *chunk_id = rx->generation * EXANIC_RX_NUM_CHUNKS + rx->next_chunk;

        /* Advance next_chunk to next chunk */
        rx->next_chunk++;
        if (rx->next_chunk == EXANIC_RX_NUM_CHUNKS)
        {
            rx->next_chunk = 0;
            rx->generation++;
        }

        *more_chunks = (u.info.length == 0);
        length = *more_chunks ? EXANIC_RX_CHUNK_PAYLOAD_SIZE : u.info.length;
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

/**
 * \brief Check if a previously read chunk has been overwritten
 *
 * \param[in]   rx
 *      A valid RX handle.
 * \param[in]   chunkid
 *      A number identifing the chunk from \ref exanic_receive_chunk_inplace().
 *
 * \return 1 if chunk is still valid, 0 if chunk has been overwritten
 */
static inline int exanic_receive_chunk_recheck(exanic_rx_t *rx,
                                               uint32_t chunk_id)
{
    uint32_t chunk = chunk_id % EXANIC_RX_NUM_CHUNKS;
    uint8_t generation = chunk_id / EXANIC_RX_NUM_CHUNKS;

    return rx->buffer[chunk].u.info.generation == generation;
}


/**
 * \brief Get the lower 32 bits of a received chunk timestamp (in cycles)
 *
 * \param[in]   rx
 *      A valid RX handle.
 * \param[in]   chunkid
 *      A number identifing the chunk from \ref exanic_receive_chunk_inplace().
 *
 * \return Timestamp if chunk is still valid, undefined otherwise
 */
static inline exanic_cycles32_t exanic_receive_chunk_timestamp(exanic_rx_t *rx,
                                                            uint32_t chunk_id)
{
    uint32_t chunk = chunk_id % EXANIC_RX_NUM_CHUNKS;
    return rx->buffer[chunk].u.info.timestamp;
}


/**
 * \brief Skip chunks until the end of a frame.
 *
 * A call to this function must have been preceded by a call to
 * \ref exanic_receive_chunk in which more_chunks was set to 1.
 *
 * \param[in]   rx
 *      A valid RX handle.
 *
 * \return 0 if success, or <0 for errors (see \ref rx_frame_status).
 */
static inline int exanic_receive_abort(exanic_rx_t *rx)
{
    while (1)
    {
        union {
            struct rx_chunk_info info;
            uint64_t data;
        } u;

        u.data = rx->buffer[rx->next_chunk].u.data;

        if (u.info.generation == rx->generation)
        {
            /* Advance next_chunk to next chunk */
            rx->next_chunk++;
            if (rx->next_chunk == EXANIC_RX_NUM_CHUNKS)
            {
                rx->next_chunk = 0;
                rx->generation++;
            }

            if (u.info.length != 0)
            {
                if (u.info.frame_status & EXANIC_RX_FRAME_ERROR_MASK)
                    return -(u.info.frame_status & EXANIC_RX_FRAME_ERROR_MASK);

                return 0;
            }
        }
        else if (u.info.generation != (uint8_t)(rx->generation - 1))
        {
            /* Got lapped? */
            __exanic_rx_catchup(rx);
            return -EXANIC_RX_FRAME_SWOVFL;
        }
    }
}

/**
 * \brief Read one chunk of data into the provided buffer, returning
 * metadata about the chunk
 *
 * \param[in]   rx
 *      A valid RX handle.
 * \param[out]  rx_buf
 *      Pointer to the user provided buffer.
 *      Must have at least \ref EXANIC_RX_CHUNK_PAYLOAD_SIZE bytes of space.
 * \param[out]  more_chunks
 *      Set to non-zero if there are more chunks in the current frame
 *      or zero if it is the last chunk. Left unchanged if no data was read.
 * \param[out]  info
 *      Returns a copy of the chunk metadata from the hardware.
 *
 * This function will return chunk data even if the frame has errors.  The
 * caller should check info.frame_status for errors (see \ref rx_frame_status).
 *
 * \return Size of the chunk, or 0 if no data available,
 *         or -EXANIC_RX_FRAME_SWOVFL if chunks were missed by software.
 */
ssize_t exanic_receive_chunk_ex(exanic_rx_t *rx, char *rx_buf, int *more_chunks,
         struct rx_chunk_info *info);

#ifdef __cplusplus
}
#endif

#endif /* EXANIC_FIFO_RX_H */
