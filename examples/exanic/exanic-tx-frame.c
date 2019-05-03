/* Basic TX example */
#include <stdio.h>
#include <string.h>
#include <exanic/exanic.h>
#include <exanic/fifo_tx.h>

int main(void)
{
    char *device = "exanic0";
    int port = 0;

    exanic_t *exanic = exanic_acquire_handle(device);
    if (!exanic)
    {
        fprintf(stderr, "exanic_acquire_handle: %s\n", exanic_get_last_error());
        return 1;
    }

    exanic_tx_t *tx = exanic_acquire_tx_buffer(exanic, port, 0);
    if (!tx)
    {
        fprintf(stderr, "exanic_acquire_tx_buffer: %s\n", exanic_get_last_error());
        return 1;
    }

    char frame[1000];
    memset(frame, 0xff, 1000);
    if (exanic_transmit_frame(tx, frame, sizeof(frame)) == 0)
        printf("Transmitted a frame\n");

    exanic_release_tx_buffer(tx);
    exanic_release_handle(exanic);
    return 0;
}
