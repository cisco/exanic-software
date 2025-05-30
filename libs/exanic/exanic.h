/**
 * \file
 * \brief Functions for acquiring handles to ExaNIC hardware
 *
 * \mainpage ExaNIC API
 *
 * The ExaNIC API is split into the following sections:
 * - \ref exanic.h "ExANIC API" (ExaNIC access)
 * - \ref fifo_rx.h "RX FIFO API" (RX FIFO access)
 * - \ref fifo_tx.h "TX FIFO API" (TX FIFO access)
 * - \ref port.h "Port config API" (ExaNIC port configuration)
 * - \ref config.h "Network config API" (Network settings)
 * - \ref time.h "Timestamping API" (Timestamp conversion functions)
 */
#ifndef EXANIC_EXANIC_H
#define EXANIC_EXANIC_H

#include <stdint.h>
#include <stdlib.h>

#include "const.h"
#include "hw_info.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DEVICE_NAME_LEN 64

/**
 * \brief A ExaNIC handle.
 */
typedef struct exanic
{
    int                     ref_count;
    struct exanic           *next;

    volatile uint32_t       *registers;
    volatile struct exanic_info_page *info_page;
    volatile uint32_t       *devkit_regs_region;
    char                    *devkit_mem_region;
    volatile uint32_t       *devkit_regs_ex_region;
    char                    *devkit_mem_ex_region;
    volatile uint16_t       *tx_feedback_slots;
    char                    *tx_buffer;
    size_t                  tx_buffer_size;
    volatile uint32_t       *filters;
    size_t                  filters_size;
    size_t                  devkit_regs_size;
    size_t                  devkit_mem_size;
    size_t                  devkit_regs_ex_size;
    size_t                  devkit_mem_ex_size;
    uint32_t                tick_hz;
    uint32_t                caps;
    int                     fd;
    char                    name[16];
    unsigned int            max_filter_buffers;
    /* number of ethernet interfaces
     * can differ from the number of physical ports */
    unsigned int            num_ports;
    int                     if_index[EXANIC_MAX_PORTS];
    struct exanic_hw_info   hw_info;
} exanic_t;

/**
 * \brief Acquire a ExaNIC handle
 *
 * \param[in]   device_name
 *      The ExaNIC device
 *
 * \return A valid ExaNIC handle, or NULL if an error occurred
 *
 * \warning Handles to ExaNICs are shared and reference-counted.  Multiple
 * calls to \ref exanic_acquire_handle with the same device name will return
 * the same pointer.
 */
exanic_t * exanic_acquire_handle(const char *device_name);

/**
 * \brief Increment the reference count on a ExaNIC handle.
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 */
void exanic_retain_handle(exanic_t *exanic);

/**
 * \brief Release a ExaNIC handle
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 */
void exanic_release_handle(exanic_t *exanic);

/**
 * \brief Get an error string describing the last libexanic error
 *
 * \return A pointer to a string
 */
const char * exanic_get_last_error(void);

void exanic_err_printf(const char * fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* EXANIC_EXANIC_H */
