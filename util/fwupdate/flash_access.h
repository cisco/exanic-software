#ifndef _EXANIC_FWUPDATE_FLASH_ACCESS_H
#define _EXANIC_FWUPDATE_FLASH_ACCESS_H

#include <stdint.h>
#include <stdbool.h>
#include <exanic/exanic.h>

typedef uint16_t flash_word_t;
typedef uint32_t flash_address_t;
typedef uint32_t flash_size_t;

#define BYTES_IN_FLASH_WORDS (sizeof(flash_word_t) / sizeof(char))

struct flash_ops;

struct flash_device
{
    exanic_t *exanic;
    struct flash_ops *ops;
    bool is_recovery;
    flash_size_t device_size;
    flash_address_t partition_start;
    flash_size_t partition_size;
    flash_size_t main_block_size;
    flash_size_t region_1_block_size;
    flash_address_t region_2_start;
    flash_size_t region_2_block_size;
    flash_address_t region_3_start;
    flash_size_t region_3_block_size;
    flash_size_t burst_buffer_size;
    flash_size_t min_read_size;
    uint32_t status;
};

struct flash_ops
{
    bool (*init)(struct flash_device *flash);
    bool (*erase_block)(struct flash_device *flash, flash_address_t address);
    bool (*burst_program)(struct flash_device *flash, flash_address_t address,
            flash_word_t *data, flash_size_t size);
    bool (*read)(struct flash_device *flash, flash_address_t address,
            flash_word_t *data, flash_size_t size);
    void (*release)(struct flash_device *flash);
};

struct flash_device *flash_open(exanic_t *exanic, bool recovery_partition, flash_size_t *partition_size);
bool flash_erase(struct flash_device *flash, flash_size_t size, void (*report_progress)());
bool flash_program(struct flash_device *flash, flash_word_t *data, flash_size_t size, void (*report_progress)());
bool flash_verify(struct flash_device *flash, flash_word_t *data, flash_size_t size, void (*report_progress)());
void flash_close(struct flash_device *flash);

#endif /* _EXANIC_FWUPDATE_FLASH_ACCESS_H */
