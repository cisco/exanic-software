/* Basic RX example */
#include <stdio.h>
#include <exanic/exanic.h>
#include <exanic/fifo_rx.h>

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

    exanic_rx_t *rx = exanic_acquire_rx_buffer(exanic, port, 0);
    if (!rx)
    {
        fprintf(stderr, "exanic_acquire_rx_buffer: %s\n", exanic_get_last_error());
        return 1;
    }

    char buf[2048];
    exanic_cycles32_t timestamp;

    while (1)
    {
        ssize_t sz = exanic_receive_frame(rx, buf, sizeof(buf), &timestamp);
        if (sz > 0)
        {
            printf("Got a valid frame\n");
            break;
        }
    }

    exanic_release_rx_buffer(rx);
    exanic_release_handle(exanic);
    return 0;
}
