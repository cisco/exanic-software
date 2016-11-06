/**
 * Very basic example showing how to arbitrarily divide up the ExaNIC TX buffer,
 * then load a number of frames into each slot and choose one to send later. The
 * general idea is to remove the overhead of transferring the packet to the card
 * from the critical path. In many cases you may know ahead of time the message
 * you want to send, so we can push these to the card, then pick one to send at
 * a later time. This way we only incur the latency of the transmit command.
 */
#include <stdio.h>
#include <string.h>
#include <exanic/fifo_tx.h>
#include <exanic/exanic.h>
#include <unistd.h>

/* Not used here - chunks must be QWORD aligned though. */
#define QWORD_ALIGN(x) (((x) + 7) & ~7)

/*
 * Arbitrary maximum chunk size. Size this is a multiple of QWORD size, we don't
 * need to explicity QWORD align.
 */
#define TX_SLOT_SIZE 256

/* Configure the header for a given slot. */
void set_slot_header(exanic_tx_t *tx, int slot, int length)
{
    struct tx_chunk *chunk =
        (struct tx_chunk *) (tx->buffer + TX_SLOT_SIZE * slot);
    size_t padding = exanic_payload_padding_bytes(EXANIC_TX_TYPE_RAW);

    chunk->feedback_id = 0x0000;            /* Not applicable. */
    chunk->feedback_slot_index = 0x8000;    /* No feedback. */
    chunk->length = padding + length ;      /* Frame size + padding. */
    chunk->type = EXANIC_TX_TYPE_RAW;       /* Only supported transmit type. */
    chunk->flags = 0;
}

/* Get a pointer to the payload for a given slot. */
char * get_slot_payload(exanic_tx_t *tx, int slot)
{
    struct tx_chunk *chunk =
        (struct tx_chunk *) (tx->buffer + TX_SLOT_SIZE * slot);
    size_t padding = exanic_payload_padding_bytes(EXANIC_TX_TYPE_RAW);

    return chunk->payload + padding;
}

/*
 * Force the write combining buffers to be flushed after pushing all of the
 * frames to the card.
 */
void flush_wc_buffers(exanic_tx_t *tx)
{
    /*
     * This should trigger a write combining flush. It is a dummy write to a
     * read only register.
     */
    tx->exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_PCIE_IF_VER)]
        = 0xDEADBEEF;

    /* --> this may work too: asm volatile ("sfence" ::: "memory"); */
}

/* Trigger a send on a given slot. */
void trigger_slot_send(exanic_tx_t *tx, int slot)
{
    int offset = slot * TX_SLOT_SIZE;
    tx->exanic->registers[REG_PORT_INDEX(tx->port_number, REG_PORT_TX_COMMAND)]
        = offset + tx->buffer_offset;
}

const char fake_mac_addr[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};
void generate_packet(char *packet, size_t size, uint8_t content)
{
    /* Set source and destination MAC address */
    memset(packet, 0xFF, 6);
    memcpy(&packet[6], fake_mac_addr, 6);

    /* IP packet */
    packet[12] = 0x08;
    packet[13] = 0x00;

    /* Zero IP header area */
    memset(&packet[14], 0, 20);

    /* Fill packet with content */
    memset(&packet[34], content, size-34 );
}

int main(void)
{
    int port_number = 0;
    char device[10] = "exanic0";
    unsigned buffer_size = 0x1000;
    exanic_t *exanic;
    exanic_tx_t *tx;
    int i;
    unsigned packet_size;
    char * payload;

    if ((exanic = exanic_acquire_handle(device)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return -1;
    }

    /* Reserve some space in the TX buffer. */
    tx = exanic_acquire_tx_buffer(exanic, port_number, buffer_size);

    /*
     * In this example, we partition the TX buffer into a number of slots, each
     * TX_SLOT_SIZE bytes in length. The actual packet length is smaller than
     * this (each slot must store a struct tx_chunk, padding and payload).
     */
    for (i = 0; i < 4; i++)
    {
        /*
         * Generate 4 dummy packets, write them directly into the transmit
         * buffer.
         */
        payload = get_slot_payload(tx, i);
        /*
         * By way of example, grow the packet size by 20 bytes each time.
         * NB the smallest packet is 60 bytes plus 4 bytes of CRC the FPGA
         * add
         */
        packet_size = 60 + i*20;
        set_slot_header(tx, i, packet_size);
        generate_packet(payload, packet_size, i);
    }

    /*
     * Force a flush of the write combining buffers to sync everything to the
     * card. We do this because the ExaNIC transmit buffers are mapped in write
     * combining mode, which means that multiple writes can get buffered and
     * sent together. Normally this isn't an issue because we aren't pre-loading
     * but in this example we want all the data to be in the tx buffer well
     * ahead of time, so the transmit latency is just the time to send a command
     * to BAR0 (ie just hit the transmit register)
     */
    flush_wc_buffers(tx);

    /*
     * Trigger a send from each slot spaced 1 sec apart.
     * Note: To avoid overflowing the TX command queue, the software should make
     * sure that no more than buffer_size/EXANIC_TX_CMD_FIFO_SIZE_DIVISOR
     * transmit commands are in flight at any one time. The TX feedback
     * mechanism (not used in this example) can be used to notify the software
     * when a transmit command is finished.
     */
    for (i = 0; i < 4; i++)
    {
        trigger_slot_send(tx, i);
        usleep(1000000);
    }

    return 0;
}
