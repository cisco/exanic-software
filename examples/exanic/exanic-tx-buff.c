/*
 * This program displays total and available unused TX buffer size.
 *
 * Usage:
 *    ./exanic-tx-buff exanic0
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <exanic/exanic.h>
#include <exanic/fifo_tx.h>
#include <exanic/fifo_if.h>
#include <exanic/register.h>

int main(int argc, char *argv[])
{
    char *device;
    exanic_t *exanic;
    exanic_tx_t *exanic_tx;
    ssize_t tx_buf_size;

    if (argc < 2) {
        fprintf(stderr, "Device name not specified.\n");
        return EXIT_FAILURE;
    }

    device = argv[1];
    if (strlen(device) >= 16) {
        fprintf(stderr, "Device name too long.\n");
        return EXIT_FAILURE;
    }

    exanic = exanic_acquire_handle(device);
    if (exanic == NULL) {
        fprintf(stderr, "exanic_acquire_handle : %s\n",
                exanic_get_last_error());
        return EXIT_FAILURE;
    }

    for (int i = 0; i < exanic->num_ports; i++) {
        printf("%s port %d\n", device, i);
        tx_buf_size = exanic_register_read(exanic,
                REG_PORT_INDEX(i, REG_PORT_TX_REGION_SIZE));
        printf("\tTotal Tx buffer size\t\t%ld\n", tx_buf_size);
        for (; tx_buf_size > 0; tx_buf_size -= PAGE_SIZE) {
            exanic_tx = exanic_acquire_tx_buffer(exanic, i, tx_buf_size);
            if (exanic_tx) {
                exanic_release_tx_buffer(exanic_tx);
                printf("\tAvailable Tx buffer size\t%ld\n", tx_buf_size);
                break;
            }
        }
    }
    exanic_release_handle(exanic);

    return EXIT_SUCCESS;
}
