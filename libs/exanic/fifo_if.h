/**
 * \file
 * \brief This file defines the format of the RX and TX buffers for sending
 * and receiving data on an ExaNIC.
 */
#ifndef EXANIC_FIFO_IF_H
#define EXANIC_FIFO_IF_H

#include "pcie_if.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Metadata about an RX chunk
 *
 * The ExaNIC writes RX chunks into host memory as it receives data.
 */
struct rx_chunk_info
{
    /**
     * The hardware timestamp for this RX chunk.  This records the value of
     * the ExaNIC clock counter at the start of the frame.
     */
    uint32_t timestamp;

    /**
     * The frame status.  This value is only meaningful when processing the
     * last chunk, or when determining the filter region.
     * See \ref rx_frame_status.
     */
    uint8_t frame_status;

    /**
     * The number of bytes in the payload.  A value of 0 means that the entire
     * payload is full, with more chunks to come.
     */
    uint8_t length;

    /**
     * If this frame has ended up in a filter buffer, this field indicates the
     * rule number that caused it to end up there.
     */
    uint8_t matched_filter;

    /**
     * The chunk's generation number.  This number gets incremented every time
     * the ExaNIC makes a lap around the RX ring buffer.
     */
    uint8_t generation;
};

/**
 * \brief The RX chunk
 *
 * The ExaNIC writes RX chunks into host memory as it receives data.
 */
struct rx_chunk
{
    /**
     * The payload from the RX engine.
     */
    char payload[EXANIC_RX_CHUNK_PAYLOAD_SIZE];

    /**
     * Info about this RX chunk
     */
    union {
        struct rx_chunk_info info;
        uint64_t data;
    } u;
};

/**
 * \brief Describes the state of a received frame.
 */
enum rx_frame_status
{
    /** The frame is good for further processing. */
    EXANIC_RX_FRAME_OK              = 0,

    /** The frame was aborted by the sender. */
    EXANIC_RX_FRAME_ABORTED         = 1,

    /** The frame failed the hardware CRC check. */
    EXANIC_RX_FRAME_CORRUPT         = 2,

    /**
     * One or more frames were lost due to hardware overflow
     * (insufficient PCIe/memory bandwidth).
     */
    EXANIC_RX_FRAME_HWOVFL          = 3,

    /** Mask used to detect the presence of an error. */
    EXANIC_RX_FRAME_ERROR_MASK      = 0x0F,

    /** Mask used to mask off the filter region bits. */
    EXANIC_RX_FRAME_FILTER_REGION   = 0xF0,
};

/**
 * \brief The TX chunk
 *
 * This is used to instruct a TX engine on how to transmit data.
 */
struct tx_chunk
{
    /**
     * This ID will be written into the feedback buffer at \ref
     * feedback_slot_index after this chunk has been serviced.
     */
    uint16_t    feedback_id;

    /**
     * The index of the slot within the feedback buffer for the TX engine to
     * write \ref feedback_id after this chunk has been serviced.
     *
     * The MSB (bit 15) can be set to indicate that no feedback is needed.
     */
    uint16_t    feedback_slot_index;

    /**
     * The number of bytes in \ref payload (including any padding at the
     * beginning of the payload).
     */
    uint16_t    length;

    /**
     * The \ref exanic_tx_type_id_t of the payload.
     */
    uint8_t     type;

    /**
     * Any flags to be passed to the TX engine.
     */
    uint8_t     flags;

    /**
     * The payload for the TX engine.
     *
     * \note The actual data to transmit may not begin at the beginning of the
     * payload due to padding.  See \ref exanic_payload_padding_bytes.
     */
    char        payload[0];
};

/**
 * \brief Payload metadata fields sent as a part of the TX chunk payload.
 *
 * Used only in \ref EXANIC_TX_TYPE_TCP_ACCEL type payload.
 */
struct tx_payload_metadata
{
    /**
     * The payload checksum value, big endian
     */
    uint16_t csum;

    /**
     * ATE connection ID, little endian
     */
    uint16_t connection_id;

    /**
     * DMA engine requires the whole structure to be at least 16 bytes long.
     * The structure is padded out to 18-byte long to ease TCP packet
     * formatting in ATE firmware.
     */
    uint8_t _reserved[14];

    /**
     * TCP payload starts here
     */
    char    payload[0];
};

/**
 * \brief Returns the number of padding bytes for a payload of the given type.
 *
 * \param[in]   type
 *      The \ref exanic_tx_type_id_t of the payload.
 *
 * \return The number of padding bytes for a payload of the given type.  Unknown
 * types are assumed to have no padding.
 */
static inline unsigned exanic_payload_padding_bytes(exanic_tx_type_id_t type)
{
    /*
     * This was originally derived from trying to align the data after a
     * 14-byte ethernet header. However, it's inconvenient for the hardware to
     * change the padding expectation for each TX type, so unless you're
     * really sure, stick with the original 2-byte padding.
     */
    switch (type)
    {
        case EXANIC_TX_TYPE_RAW:
        case EXANIC_TX_TYPE_TCP_ACCEL:
            return 2;
        default:
            return 0;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* EXANIC_FIFO_IF_H */
