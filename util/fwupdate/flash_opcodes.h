#ifndef _EXANIC_FWUPDATE_FLASH_OPCODES_H
#define _EXANIC_FWUPDATE_FLASH_OPCODES_H

/* generic Common Flash Interface opcodes */
#define CFI_READ_ARRAY               0xFF
#define CFI_QUERY_ADDRESS            0x55
#define CFI_QUERY_DATA               0x98

/* Intel/P30 specific opcodes */
#define P30_SET_CR_SETUP             0x60
#define P30_SET_CR_CONFIRM           0x03
#define P30_CLEAR_STATUS_REG         0x50
#define P30_UNLOCK_BLOCK_SETUP       0x60
#define P30_UNLOCK_BLOCK_CONFIRM     0xD0
#define P30_BLOCK_ERASE_SETUP        0x20
#define P30_BLOCK_ERASE_CONFIRM      0xD0
#define P30_BUFFER_PROGRAM_SETUP     0xE8
#define P30_BUFFER_PROGRAM_CONFIRM   0xD0
/* Intel/P30 status register masks */
#define P30_STATUS_READY_MASK        0x80
#define P30_STATUS_ERROR_MASK        0x30
/* Value to program to P30 config register */
#define P30_CR_CONFIG                0x9803

/* AMD/MT28 specific opcodes */
#define MT28_UNLOCK_ADDRESS_1        0x555
#define MT28_UNLOCK_DATA_1           0xAA
#define MT28_UNLOCK_ADDRESS_2        0x2AA
#define MT28_UNLOCK_DATA_2           0x55
#define MT28_UNLOCK_BYPASS_ADDRESS   0x555
#define MT28_UNLOCK_BYPASS_DATA      0x20
#define MT28_UNLOCK_BYPASS_RESET     0x90 
#define MT28_BLOCK_ERASE_SETUP       0x80
#define MT28_BLOCK_ERASE_CONFIRM     0x30
#define MT28_BUFFER_PROGRAM_SETUP    0x25
#define MT28_BUFFER_PROGRAM_CONFIRM  0x29
#define MT28_READ_ARRAY              0xF0
/* AMD/MT28 status register masks */
#define MT28_STATUS_TOGGLE_MASK      0x40
#define MT28_STATUS_ERASE_ERROR_MASK 0x20
#define MT28_STATUS_PROGRAM_ERROR_MASK 0x22

#endif /* _EXANIC_FWUPDATE_FLASH_OPCODES_H */
