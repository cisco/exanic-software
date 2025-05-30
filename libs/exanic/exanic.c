#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "exanic.h"
#include "pcie_if.h"
#include "hw_info.h"
#include "ioctl.h"

static exanic_t *exanic_list = NULL;

exanic_t * exanic_acquire_handle(const char *device_name)
{
    char device_file[MAX_DEVICE_NAME_LEN];
    int i;

    /* Check if we already have a handle for the requested device */
    exanic_t *e;
    for (e = exanic_list; e != NULL; e = e->next)
        if (strncmp(e->name, device_name, sizeof(e->name)) == 0)
        {
            e->ref_count++;
            return e;
        }

    snprintf(device_file, sizeof(device_file), "/dev/%s", device_name);

    /* Open the device file */
    int fd = open(device_file, O_RDWR);
    if (fd == -1)
    {
        exanic_err_printf("device open failed: %s", strerror(errno));
        goto err_open;
    }

    struct exanicctl_info_ex2 info;
    if (ioctl(fd, EXANICCTL_INFO_EX2, &info) != 0)
    {
        struct exanicctl_info_ex old_info;
        if (ioctl(fd, EXANICCTL_INFO_EX, &old_info) != 0)
        {
            exanic_err_printf("EXANICCTL_INFO_EX failed: %s", strerror(errno));
            goto err_ioctl;
        }

        info.tx_buffer_size = old_info.tx_buffer_size;
        info.filters_size = old_info.filters_size;
        info.max_buffers = old_info.max_buffers;
        info.num_ports = 0;
        for (i = 0; i < 4; i++)
        {
            info.if_index[i] = old_info.if_index[i];
            if (info.if_index[i])
                info.num_ports++;
        }
    }

    /* Map registers */
    uint32_t *registers = mmap(NULL, EXANIC_REGS_NUM_PAGES * PAGE_SIZE,
            PROT_READ | PROT_WRITE, MAP_SHARED, fd,
            EXANIC_PGOFF_REGISTERS * PAGE_SIZE);
    if (registers == MAP_FAILED)
    {
        exanic_err_printf("registers mmap failed: %s", strerror(errno));
        goto err_mmap_registers;
    }

    uint32_t caps = registers[REG_EXANIC_INDEX(REG_EXANIC_CAPS)];
    uint32_t tick_hz = registers[REG_EXANIC_INDEX(REG_EXANIC_CLK_HZ)];
    uint32_t hwid = registers[REG_EXANIC_INDEX(REG_EXANIC_HW_ID)];

    /* Find hardware information from device table */
    struct exanic_hw_info hwinfo;
    memset(&hwinfo, 0, sizeof hwinfo);
    exanic_get_hw_info((exanic_hardware_id_t) hwid, &hwinfo);

    /* Map info page */
    struct exanic_info_page *info_page = mmap(NULL,
            EXANIC_INFO_NUM_PAGES * PAGE_SIZE, PROT_READ, MAP_SHARED, fd,
            EXANIC_PGOFF_INFO * PAGE_SIZE);
    if (info_page == MAP_FAILED)
    {
        /* Card may be unsupported or using an old driver that does not
         * support the info page.  If the info page is required to obtain
         * the time on this card, disable timestamping. */
        info_page = NULL;
        if (!(caps & EXANIC_CAP_HW_TIME_HI))
            tick_hz = 0;
    }

    /* Map TX feedback slots and TX buffer if available */
    uint16_t *feedback_slots = NULL;
    char *tx_buffer = NULL;

    if (info.tx_buffer_size > 0)
    {
        feedback_slots = mmap(NULL,
                EXANIC_TX_FEEDBACK_NUM_PAGES * PAGE_SIZE,
                PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                EXANIC_PGOFF_TX_FEEDBACK * PAGE_SIZE);
        if (feedback_slots == MAP_FAILED)
        {
            exanic_err_printf("tx feedback mmap failed: %s", strerror(errno));
            goto err_mmap_feedback;
        }

        tx_buffer = mmap(NULL, info.tx_buffer_size,
                PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                EXANIC_PGOFF_TX_REGION * PAGE_SIZE);
        if (tx_buffer == MAP_FAILED)
        {
            exanic_err_printf("tx buffer mmap failed: %s", strerror(errno));
            goto err_mmap_tx;
        }
    }

    /* Map filters if available */
    uint32_t *filters = NULL;

    if (info.filters_size > 0)
    {
        filters = mmap(NULL, info.filters_size,
                PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                EXANIC_PGOFF_FILTERS * PAGE_SIZE);
        if (filters == MAP_FAILED)
        {
            exanic_err_printf("filters mmap failed: %s", strerror(errno));
            goto err_mmap_filters;
        }
    }

    /* Map devkit regions if available. */
    struct exanicctl_devkit_info devkit_info = {0, 0};
    uint32_t *devkit_regs_region = NULL;
    void *devkit_mem_region = NULL;

    if (ioctl(fd, EXANICCTL_DEVKIT_INFO, &devkit_info) == 0)
    {
        if (devkit_info.regs_size > 0)
        {
             devkit_regs_region = mmap(NULL, devkit_info.regs_size,
                                PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                                EXANIC_PGOFF_DEVKIT_REGS * PAGE_SIZE);
            if (devkit_regs_region == MAP_FAILED)
            {
                exanic_err_printf("devkit regs mmap failed: %s", strerror(errno));
                goto err_mmap_devkit_regs;
            }
        }

        if (devkit_info.mem_size > 0)
        {
             devkit_mem_region = mmap(NULL, devkit_info.mem_size,
                                PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                                EXANIC_PGOFF_DEVKIT_MEM * PAGE_SIZE);
            if (devkit_mem_region == MAP_FAILED)
            {
                exanic_err_printf("devkit memory mmap failed: %s", strerror(errno));
                goto err_mmap_devkit_mem;
            }
        }
    }

    /* Map extended devkit regions if available */
    struct exanicctl_devkit_info devkit_info_ex = {0, 0};
    uint32_t *devkit_regs_ex_region = NULL;
    void *devkit_mem_ex_region = NULL;

    if (ioctl(fd, EXANICCTL_DEVKIT_INFO_EX, &devkit_info_ex) == 0)
    {
        if (devkit_info_ex.regs_size > 0)
        {
             devkit_regs_ex_region = mmap(NULL, devkit_info_ex.regs_size,
                                PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                                EXANIC_PGOFF_DEVKIT_REGS_EXT * PAGE_SIZE);
            if (devkit_regs_ex_region == MAP_FAILED)
            {
                exanic_err_printf("extended devkit regs mmap failed: %s", strerror(errno));
                goto err_mmap_devkit_regs_ex;
            }
        }

        if (devkit_info_ex.mem_size > 0)
        {
             devkit_mem_ex_region = mmap(NULL, devkit_info_ex.mem_size,
                                PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                                EXANIC_PGOFF_DEVKIT_MEM_EXT * PAGE_SIZE);
            if (devkit_mem_ex_region == MAP_FAILED)
            {
                exanic_err_printf("extended devkit memory mmap failed: %s", strerror(errno));
                goto err_mmap_devkit_mem_ex;
            }
        }
    }

    /* Create the exanic struct */
    exanic_t *exanic = malloc(sizeof(exanic_t));
    if (exanic == NULL)
    {
        exanic_err_printf("exanic alloc failed: %s", strerror(errno));
        goto err_mmap_devkit_mem_ex;
    }

    exanic->registers = registers;
    exanic->info_page = info_page;
    exanic->tx_feedback_slots = feedback_slots;
    exanic->devkit_regs_region = devkit_regs_region;
    exanic->devkit_regs_size = devkit_info.regs_size;
    exanic->devkit_mem_region = devkit_mem_region;
    exanic->devkit_mem_size = devkit_info.mem_size;
    exanic->devkit_regs_ex_region = devkit_regs_ex_region;
    exanic->devkit_regs_ex_size = devkit_info_ex.regs_size;
    exanic->devkit_mem_ex_region = devkit_mem_ex_region;
    exanic->devkit_mem_ex_size = devkit_info_ex.mem_size;
    exanic->tx_buffer = tx_buffer;
    exanic->tx_buffer_size = info.tx_buffer_size;
    exanic->filters = filters;
    exanic->filters_size = info.filters_size;
    exanic->tick_hz = tick_hz;
    exanic->caps = caps;
    exanic->fd = fd;
    exanic->max_filter_buffers = info.max_buffers;
    strncpy(exanic->name, device_name, sizeof(exanic->name));
    exanic->name[sizeof(exanic->name) - 1] = '\0';
    exanic->num_ports = (info.num_ports > EXANIC_MAX_PORTS) ?
                           EXANIC_MAX_PORTS : info.num_ports;
    exanic->hw_info = hwinfo;

    for (i = 0; i < exanic->num_ports; i++)
        exanic->if_index[i] = info.if_index[i];

    /* Add to list */
    exanic->ref_count = 1;
    exanic->next = exanic_list;
    exanic_list = exanic;
    return exanic;

err_mmap_devkit_mem_ex:
    if (devkit_regs_ex_region != NULL)
        munmap(devkit_regs_ex_region, devkit_info_ex.regs_size);
err_mmap_devkit_regs_ex:
    if (devkit_mem_region != NULL)
        munmap(devkit_mem_region, devkit_info.mem_size);
err_mmap_devkit_mem:
    if (devkit_regs_region != NULL)
        munmap(devkit_regs_region, devkit_info.regs_size);
err_mmap_devkit_regs:
    if (filters != NULL)
        munmap(filters, info.filters_size);
err_mmap_filters:
    if (tx_buffer != NULL)
        munmap(tx_buffer, info.tx_buffer_size);
err_mmap_tx:
    if (feedback_slots != NULL)
        munmap(feedback_slots, EXANIC_TX_FEEDBACK_NUM_PAGES * PAGE_SIZE);
err_mmap_feedback:
    if (info_page != NULL)
        munmap(info_page, EXANIC_INFO_NUM_PAGES * PAGE_SIZE);
    munmap(registers, EXANIC_REGS_NUM_PAGES * PAGE_SIZE);
err_mmap_registers:
err_ioctl:
    close(fd);
err_open:
    return NULL;
}

void exanic_retain_handle(exanic_t *exanic)
{
    exanic->ref_count++;
}

void exanic_release_handle(exanic_t *exanic)
{
    if (exanic == NULL)
        return;

    exanic->ref_count--;
    if (exanic->ref_count > 0)
        return;

    /* Remove from list */
    exanic_t *i;
    if (exanic_list == exanic)
        exanic_list = exanic_list->next;
    else for (i = exanic_list; i != NULL; i = i->next)
        if (i->next == exanic)
        {
            i->next = i->next->next;
            break;
        }

    /* Unmap buffers and free the exanic struct */
    if (exanic->devkit_mem_ex_region != NULL)
        munmap((void *)exanic->devkit_mem_ex_region, exanic->devkit_mem_ex_size);
    if (exanic->devkit_regs_ex_region != NULL)
        munmap((void *)exanic->devkit_regs_ex_region, exanic->devkit_regs_ex_size);
    if (exanic->devkit_mem_region != NULL)
        munmap((void *)exanic->devkit_mem_region, exanic->devkit_mem_size);
    if (exanic->devkit_regs_region != NULL)
        munmap((void *)exanic->devkit_regs_region, exanic->devkit_regs_size);
    if (exanic->filters != NULL)
        munmap((void *)exanic->filters, exanic->filters_size);
    if (exanic->tx_buffer != NULL)
        munmap((void *)exanic->tx_buffer, exanic->tx_buffer_size);
    if (exanic->tx_feedback_slots != NULL)
        munmap((void *)exanic->tx_feedback_slots,
                EXANIC_TX_FEEDBACK_NUM_PAGES * PAGE_SIZE);
    if (exanic->info_page != NULL)
        munmap((void *)exanic->info_page, EXANIC_INFO_NUM_PAGES * PAGE_SIZE);
    munmap((void *)exanic->registers, EXANIC_REGS_NUM_PAGES * PAGE_SIZE);
    close(exanic->fd);

    free(exanic);
}

char exanic_err_str[256];

void exanic_err_printf(const char * fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(exanic_err_str, sizeof(exanic_err_str), fmt, ap);
    va_end(ap);
}

const char * exanic_get_last_error(void)
{
    return exanic_err_str;
}

