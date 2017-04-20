/**
 * \file
 * \brief Functions for transmitting data on ExaNICs.
 */
#ifndef FIFO_TX_H_BB41CD6329C4DFF3E94B5DFA83448F89
#define FIFO_TX_H_BB41CD6329C4DFF3E94B5DFA83448F89

#include "exanic.h"
#include "pcie_if.h"
#include "fifo_if.h"
#include "time.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief A handle to a ExaNIC TX FIFO
 */
typedef struct exanic_tx
{
    exanic_t            *exanic;
    int                 port_number;
    int                 feedback_slot;
    volatile uint16_t   *feedback;
    char                *buffer;
    uint32_t            buffer_offset;
    uint32_t            buffer_size;
    uint32_t            next_offset;
    uint16_t            feedback_seq;
    uint16_t            request_seq;
    uint16_t            rollover_seq;
    uint16_t            next_seq;
    int                 queue_len;
    uint32_t            *feedback_offsets;

    struct tx_chunk     *prepared_chunk;
    size_t              prepared_chunk_size;
} exanic_tx_t;

/**
 * \brief Allocate a ExaNIC TX buffer
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle.
 * \param[in]   port_number
 *      The port number.
 * \param[in]   requested_size
 *      Requested size of the TX buffer, in bytes.  A zero region size means
 *      that the default TX buffer size will be used.
 *
 * \return A handle to the TX buffer, or NULL on error.
 *
 */
exanic_tx_t * exanic_acquire_tx_buffer(exanic_t *exanic, int port_number,
                                       size_t requested_size);

/**
 * \brief Free an ExaNIC TX buffer
 *
 * \param[in]   tx
 *      A valid TX handle.
 */
void exanic_release_tx_buffer(exanic_tx_t *tx);

/**
 * \brief Return the largest allowed frame size for the TX buffer
 *
 * \param[in]   tx
 *      A valid TX handle.
 *
 * \return The largest allowed frame size.
 */
size_t exanic_get_tx_mtu(exanic_tx_t *tx);

/**
 * \brief Transmit a frame
 *
 * \param[in]   tx
 *      A valid TX handle.
 * \param[in]   frame
 *      Pointer to the user provided buffer.
 * \param[in]   frame_size
 *      Size of the frame to transmit.
 *
 * \return 0 on success, or -1 on error.
 */
int exanic_transmit_frame(exanic_tx_t *tx, const char *frame,
                          size_t frame_size);

/**
 * \brief Allocate space in the TX buffer to start a new frame
 *
 * \param[in]   tx
 *      A valid TX handle.
 * \param[in]   frame_size
 *      Size of the frame to allocate.
 *
 * \return Pointer to the start of the allocated frame
 */
char * exanic_begin_transmit_frame(exanic_tx_t *tx, size_t frame_size);

/**
 * \brief Transmit a frame that was allocated by \ref exanic_begin_transmit_frame
 *
 * \param[in]   tx
 *      A valid TX handle.
 * \param[in]   frame_size
 *      Actual size of the frame to allocate, must be smaller than the size
 *      requested in \ref exanic_begin_transmit_frame
 *
 * \return 0 on success, or -1 on error.
 */
int exanic_end_transmit_frame(exanic_tx_t *tx, size_t frame_size);

/**
 * \brief Abort a frame that was allocated by \ref exanic_begin_transmit_frame
 *
 * \param[in]   tx
 *      A valid TX handle.
 *
 * \return 0 on success, or -1 on error.
 */
int exanic_abort_transmit_frame(exanic_tx_t *tx);

/**
 * \brief Get the 32 bit timestamp of the last frame transmitted (cycles).
 *
 * \param[in]   tx
 *      A valid TX handle.
 *
 * \return The lower 32 bits of the timestamp of the last transmitted frame
 *         (in cycles)
 *
 */
exanic_cycles32_t exanic_get_tx_timestamp(exanic_tx_t *tx);

#ifdef __cplusplus
}
#endif

#endif /* FIFO_TX_H_BB41CD6329C4DFF3E94B5DFA83448F89 */
