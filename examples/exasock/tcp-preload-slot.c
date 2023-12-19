/*
 * This program demonstrates the use of the Exasock extensions APIs and
 * direct register write to preload a tcp packet and send using trigger
 * from any available slots in the tx buffer.
 *
 * Example usage:
 *   exasock ./tcp-preload <tcp-message-size> <slot>
 *
 * The extensions API is useful for performing TCP transmission from outside of
 * standard sockets, for example, from the ExaNIC FPGA or by preloading the
 * transmit buffers on the card.
 *
 * This program will try to connect to tcp server listening on 1.1.1.2
 * and tcp port 31415. For this test IP address 1.1.1.1/24 was set on exanic
 * interface via which 1.1.1.2 was accessible. Once connection is accepted,
 * TX buffer for all the available regions are aquired for sending packets
 * stored in slots with max packet size 256 bytes each.
 *
 * Note that if run without Exasock this example will fail.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <exasock/extensions.h>
#include <exanic/exanic.h>
#include <exanic/fifo_tx.h>
#include <exanic/fifo_if.h>
#include <exanic/register.h>

#define SERVER_IP_ADDR      "1.1.1.2"
#define SERVER_TCP_PORT     31415

/* Not used here - chunks must be QWORD aligned though. */
#define QWORD_ALIGN(x) (((x) + 7) & ~7)

/*
 * Arbitrary maximum chunk size. Size this is a multiple of QWORD size, we don't
 * need to explicity QWORD align.
 */
#define TX_SLOT_SIZE 256

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

void fill(char *buf, int len)
{
#define ascii() ('a' + rand() % ('z' - 'a' + 1))
    for (int i = 0; i < len - 1; i++)
        buf[i] = ascii();
}

int main(int argc, char *argv[])
{
    struct sockaddr_in sa;
    char *reqpkt;
    char buf[1024];
    char device[16];
    int fd, ret = 0, port_number;
    ssize_t len, hdr_len;
    exanic_t *exanic;
    exanic_tx_t *exanic_tx;
    ssize_t payload_sz = 0, max_payload_size, tx_buf_size;
    int slot = 0;

    if (argc < 2) {
        fprintf(stderr, "payload size is not given\n");
        return EXIT_FAILURE;
    }

    if (argc < 3) {
        fprintf(stderr, "slot is not given\n");
        return EXIT_FAILURE;
    }

    payload_sz = atoi(argv[1]);
    slot = atoi(argv[2]);

    srand(time(NULL));
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "Socket %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    /* connect to test server */
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_aton(SERVER_IP_ADDR, &sa.sin_addr);
    sa.sin_port = htons(SERVER_TCP_PORT);
    ret = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (ret != 0) {
        fprintf(stderr, "Connect : %s\n", strerror(errno));
        ret = -1;
        goto err_attach_device;
    }

    /* set up libexanic handle */
    ret = exasock_tcp_get_device(fd, device, sizeof(device), &port_number);
    if (ret != 0) {
        fprintf(stderr, "exasock_tcp_get_device : %s\n", strerror(errno));
        ret = -1;
        goto err_attach_device;
    }
    exanic = exanic_acquire_handle(device);
    if (exanic == NULL) {
        fprintf(stderr, "exanic_acquire_handle : %s\n",
                exanic_get_last_error());
        ret = -1;
        goto err_attach_device;
    }

    /* Get available Tx buffer size from registers.
     * Decrease (2 * PAGE_SIZE) from total TX buffer which are
     * used by exanic kernel driver and this socket 'connect' API
     * when exasock accelerated. */
    tx_buf_size = exanic_register_read(exanic,
            REG_PORT_INDEX(port_number, REG_PORT_TX_REGION_SIZE)) - (2 * PAGE_SIZE);
    printf("tx_buf_size %ld MAX slots available = %ld\n",
            tx_buf_size, tx_buf_size / TX_SLOT_SIZE);
    if (slot >= tx_buf_size / TX_SLOT_SIZE) {
        fprintf(stderr, "Slot number too high, choose a slot 0 - %ld\n",
                tx_buf_size / TX_SLOT_SIZE - 1);
        ret = -1;
        goto err_tx_buffer;
    }

    exanic_tx = exanic_acquire_tx_buffer(exanic, port_number, tx_buf_size);
    if (exanic_tx == NULL) {
        fprintf(stderr, "exanic_acquire_tx_buffer : %s\n",
                exanic_get_last_error());
        ret = -1;
        goto err_tx_buffer;
    }

    reqpkt = get_slot_payload(exanic_tx, slot);

    hdr_len = exasock_tcp_build_header(fd, buf, sizeof(buf), 0, 0);
    if (hdr_len <= 0) {
        fprintf(stderr, "exasock_tcp_build_header : %s\n", strerror(errno));
        ret = -1;
        goto err_exasock;
    }

    /* calculate maximum tcp payload size in this slot */
    max_payload_size = TX_SLOT_SIZE - hdr_len - sizeof(struct tx_chunk)
        - exanic_payload_padding_bytes(EXANIC_TX_TYPE_RAW);
    if (payload_sz > max_payload_size) {
        fprintf(stderr, "Payload size too high (allowed is upto %ld)\n",
                max_payload_size);
        ret = -1;
        goto err_exasock;
    }

    /* fill payload with random ascii values */
    fill(buf + hdr_len, payload_sz);

    ret = exasock_tcp_set_length(buf, hdr_len, payload_sz);
    if (ret != 0) {
        fprintf(stderr, "exasock_tcp_set_length : %s\n", strerror(errno));
        ret = -1;
        goto err_exasock;
    }

    ret = exasock_tcp_calc_checksum(buf, hdr_len, buf + hdr_len, payload_sz);
    if (ret != 0) {
        fprintf(stderr, "exasock_tcp_calc_checksum : %s", strerror(errno));
        ret = -1;
        goto err_exasock;
    }

    set_slot_header(exanic_tx, slot, hdr_len + payload_sz);
    memcpy(reqpkt, buf, hdr_len + payload_sz);

    /*
     * Force a flush of the write combining buffers to sync everything to the
     * card. We do this because the ExaNIC transmit buffers are mapped in write
     * combining mode, which means that multiple writes can get buffered and
     * sent together. Normally this isn't an issue because we aren't pre-loading
     * but in this example we want all the data to be in the tx buffer well
     * ahead of time, so the transmit latency is just the time to send a command
     * to BAR0 (ie just hit the transmit register)
     */
    flush_wc_buffers(exanic_tx);

    /* send message */
    trigger_slot_send(exanic_tx, slot);

    printf("len %ld ; %s\n", hdr_len + payload_sz, buf + hdr_len);
    /* wait to receive string message from server*/
    len = read(fd, buf, sizeof(buf));
    if (len > 0) {
        printf("%s\n", buf);
    }

err_exasock:
    exanic_release_tx_buffer(exanic_tx);
err_tx_buffer:
    exanic_release_handle(exanic);
err_attach_device:
    close(fd);

    return ret;
}
