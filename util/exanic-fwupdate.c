#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>

#include <exanic/exanic.h>
#include <exanic/pcie_if.h>
#include <exanic/register.h>

#define CR_DEFAULT                  (0x9803) // everything except bit 15 is don't care
#define FLASH_VENDOR_ID             (0x89)
#define FLASH_DEVICE_ID             (0x8818)

/* Flash config. register bit positions */
#define READ_MODE_BIT_POS           15 // micron

/* Config. register bit masks */
#define ASYC_READ_MODE_MASK         (1UL << READ_MODE_BIT_POS ) // micron

/* FPGA register addresses, bit positions, masks, etc */

#define EXANIC_FLASH_ADDR_REG_ADDR  (0x4F)
#define EXANIC_FLASH_DIN_BUS_ADDR   (0x52)
#define EXANIC_FLASH_DOUT_BUS_ADDR  (0x50)
#define EXANIC_FLASH_CTRL_REG_ADDR  (0x51)

/* FPGA control register bit definitions */
#define FLASH_TO_FPGA               0UL
#define FPGA_TO_FLASH               1UL

#define RESET_BIT_POS               5
#define DATA_DIR_BIT_POS            4
#define LATCH_EN_BIT_POS            3
#define OUTPUT_ENABLE_BIT_POS       2
#define CHIP_EN_BIT_POS             1
#define WRITE_ENABLE_BIT_POS        0

#define LATCH_EN_BIT_MASK           (1UL << LATCH_EN_BIT_POS)
#define CHIP_EN_BIT_MASK            (1UL << CHIP_EN_BIT_POS)
#define OUTPUT_ENABLE_BIT_MASK      (1UL << OUTPUT_ENABLE_BIT_POS)
#define WRITE_ENABLE_BIT_MASK       (1UL << WRITE_ENABLE_BIT_POS)
#define DATA_DIR_BIT_MASK           (1UL << DATA_DIR_BIT_POS)
#define RESET_BIT_MASK              (1UL << RESET_BIT_POS)

#define nL                          LATCH_EN_BIT_MASK
#define nG                          OUTPUT_ENABLE_BIT_MASK
#define nE                          CHIP_EN_BIT_MASK
#define nW                          WRITE_ENABLE_BIT_MASK
#define RST                         RESET_BIT_MASK

#define FLASH_ADDR_BUS_MASK         ((1UL << 27) - 1)
#define FLASH_DATA_BUS_MASK         ((1UL << 16) - 1)
#define EXANIC_FLASH_STAT_REG_MASK  ((1UL << 8) - 1)
#define EXANIC_FLASH_CTRL_REG_MASK  ((1UL << 6) - 1)

/* Xilinx platform flash command codes */
#define SET_CR_SETUP            (0x60UL) // micron
#define SET_CR_CONFIRM          (0x03UL) // micron

#define BLOCK_UNLOCK_SETUP      (0x60UL) // micron
#define BLOCK_UNLOCK_CONFRM     (0xD0UL) // micron

#define LOCK_BLOCK_SETUP        (0x60UL)
#define LOCK_BLOCK_CONFIRM      (0x01UL)

#define UNLOCK_BLOCK_SETUP      (0x60UL)
#define UNLOCK_BLOCK_CONFIRM    (0xD0UL)

#define CLEAR_STATUS_REG        (0x50UL) // micron
#define READ_STATUS_REG         (0x70UL) // micron
#define READ_ARRAY              (0xFFUL) // micron

#define READ_ELEC_SIG           (0x90UL)
#define READ_ID                 READ_ELEC_SIG // micron

#define BLOCK_ERASE_SETUP       (0x20UL) // micron
#define BLOCK_ERASE_CONFRM      (0xD0UL) // micron

#define PROGRAM_SETUP           (0x41UL)
#define BUFFER_PROGRAM          (0xE8UL)
#define BLANK_CHECK_CONFIRM     (0xD0UL)

#define BUFFER_PROGRAM_CONFRM   (0xD0UL)
#define BLANK_CHECK_SETUP       (0xBCUL) // micron

/* Platform flash status register bits */
#define PEC_STATUS_BIT_POS              7   /* Program/Erase controller status */
#define ERASE_SUSPEND_STATUS_BIT_POS    6
#define ERASE_CHECK_STATUS_BIT_POS      5
#define PROGRAM_STATUS_BIT_POS          4
#define VPP_STATUS_BIT_POS              3
#define PROGRAM_SUSPEND_STATUS_BIT_POS  2
#define BLOCK_PROTECT_STATUS_BIT_POS    1
#define BANK_WRITE_STATUS_BIT_POS       0

/* Platform flash Electronic signature register offsets */
#define ESR_MANUFACTURER_CODE_OFFSET    0
#define ESR_DEVICE_CODE_OFFSET          1
#define ESR_BLOCK_PROTECT_OFFSET        2
#define BLOCK_LOCK_STATUS_OFFSET        ESR_BLOCK_PROTECT_OFFSET

#define PEC_STATUS_MASK                 (1UL << PEC_STATUS_BIT_POS)
#define ERASE_SUSPEND_STATUS_MASK       (1UL << ERASE_SUSPEND_STATUS_BIT_POS)
#define ERASE_CHECK_STATUS_MASK         (1UL << ERASE_CHECK_STATUS_BIT_POS)
#define PROGRAM_STATUS_MASK             (1UL << PROGRAM_STATUS_BIT_POS)
#define VPP_STATUS_MASK                 (1UL << VPP_STATUS_BIT_POS)
#define PROGRAM_SUSPEND_STATUS_MASK     (1UL << PROGRAM_SUSPEND_STATUS_BIT_POS)
#define BLOCK_PROTECT_STATUS_MASK       (1UL << BLOCK_PROTECT_STATUS_BIT_POS)
#define BANK_WRITE_STATUS_MASK          (1UL << BANK_WRITE_STATUS_BIT_POS)

/* MCS record type identifiers */
#define MCS_PROM_DATA_RECORD            (0x00)
#define MCS_PROM_EOF_RECORD             (0x01)
#define MCS_PROM_EXT_LIN_ADDR_RECORD    (0x04)

/*
 * P30 details - 23 address bits
 *
 * 128 blocks per device
 * Each block contains 64 Kwords, i.e. 64 * 1024 * 2 bytes (0x20000)
 */
#define BLOCK_ADDR_WIDTH                    7
#define BLOCK_ADDR_OFFSET                   15
#define WORDS_PER_BUFFERED_WRITE            256
#define BLOCK_ADDRESS_MASK                  ((~0) << BLOCK_ADDR_OFFSET)

#define SR_ERR_BITS_OFFSET                  4
#define SR_BLOCK_LOCK_ERR_BIT_OFFSET        1

#define SR_BLANK_CHECK_ERR_BITS             SR_PROG_ERROR_BITS
#define SR_ERASE_ERROR_BITS                 SR_PROG_ERROR_BITS
#define SR_PROG_ERROR_BITS(SR)              ((SR >> SR_ERR_BITS_OFFSET) & 0x2)
#define SR_BLOCK_LOCK_ERR_BIT(SR)           ((SR >> SR_BLOCK_LOCK_ERR_BIT_OFFSET) & 0x1)

/* Selector for the upper half of the flash, which varies based on the flash
 * device used. */
#define EXANIC_X4_UPPER_LOC_OFFSET          (1U << 23)
#define EXANIC_X10_UPPER_LOC_OFFSET         (1U << 24)

struct mcs_record_s {
  int cmd;
  int byte_count;
  int record_type;
  unsigned int address;
  int checksum;
  unsigned int payload[16];
};

typedef struct mcs_record_s mcs_record_t;

unsigned long read_exanic_flash_ctrl_reg(exanic_t *regs);
void write_exanic_flash_ctrl_reg(unsigned long value, exanic_t *regs);
unsigned long get_data_dir(void);
void set_data_dir(unsigned long dir, exanic_t *regs);
unsigned long single_cycle_async_read(unsigned long reg_addr, exanic_t *regs);
void single_cycle_write(unsigned long addr_bus, unsigned long data_bus, exanic_t *regs);
void set_read_mode_async(exanic_t *regs);
void set_flash_ctrl_bit(unsigned long mask, exanic_t *regs);
void clear_flash_ctrl_bit(unsigned long mask, exanic_t *regs);
unsigned long read_data(exanic_t *regs);
void write_data(unsigned long data, exanic_t *regs);
void drive_address(unsigned long addr, exanic_t *regs);
int check_target_hardware(char *header, exanic_t *regs);
int check_prom(char **prom);
long int prom_line_checksum(char *p);
void clear_status_register(exanic_t *regs);
void clear_status_register_addr(unsigned long addr, exanic_t *regs);
unsigned long read_status_register(unsigned long addr, exanic_t *regs);
void single_word_write(unsigned long addr, unsigned int data, exanic_t *regs);
void unlock_all_blocks(void);
int buffered_write(char **prom_data);
int parse_mcs_record(char *char_record, mcs_record_t *parsed_record);
int parse_mcs_record16(char *char_record, mcs_record_t *parsed_record);
int verify_download(char **prom_data, exanic_t *regs);
int check_mcs_data_record(mcs_record_t *parsed_record, unsigned long _base_address, exanic_t *regs);
unsigned long address_adjust(unsigned long mcs_address);
void range_unlock_and_erase(int init_partn, int fin_partn,
                              int init_blk, int fin_blk, exanic_t *regs);
inline unsigned long wait_for_device(unsigned long addr, exanic_t *regs);

static unsigned long exanic_flash_ctrl_reg = 0;
static int upper = 1; // default working on the upper image
static uint32_t global_hw_id; /* Current hardware id. */

#define UPPER_BYTE(x) ((x >> 8) & 0xFF)
#define LOWER_BYTE(x) ((x >> 0) & 0xFF)

static inline int get_upper_offset(void)
{
    switch (global_hw_id)
    {
        case EXANIC_HW_X10:
        case EXANIC_HW_X10_GM:
        case EXANIC_HW_X10_HPT:
        case EXANIC_HW_X40:
            return EXANIC_X10_UPPER_LOC_OFFSET;
        default:
            return EXANIC_X4_UPPER_LOC_OFFSET;
    }
}

static inline int get_num_blocks(void)
{
    switch (global_hw_id)
    {
        case EXANIC_HW_X10:
        case EXANIC_HW_X10_GM:
        case EXANIC_HW_X10_HPT:
        case EXANIC_HW_X40:
            return 63;
        default:
            return 31;
    }
}

int check_mcs_data_record(mcs_record_t *parsed_record, unsigned long _base_address, exanic_t *regs)
{
  unsigned int readback_data;
  unsigned long start_addr = parsed_record->address + _base_address; //+ 0x2000000;
  int i;

  single_cycle_write((start_addr>>1), READ_ARRAY, regs);    /* make sure the block is in read array mode */

  for(i = 0; i < parsed_record->byte_count; i+=2){
    readback_data = single_cycle_async_read((start_addr + i)>>1, regs) & 0xFFFF;
    if( ((readback_data & 0xFF) != parsed_record->payload[i]) ||
        ( ((readback_data >> 8) & 0xFF) != parsed_record->payload[i+1])){
      printf("ERROR: Readback mismatch\n");
      printf("Readback addr: 0x%lx\n", (start_addr + i)>>1);
      printf("Readback data: 0x%04x\n", readback_data);
      printf("Expected byte 0: 0x%02x\n", parsed_record->payload[i]);
      printf("Expected byte 1: 0x%02x\n", parsed_record->payload[i+1]);
      return -1;
    }
  }

  return 0;

}

int verify_download(char **prom_data, exanic_t *regs)
{
  unsigned long _base_address; 
  mcs_record_t parsed_record;
  _base_address = (upper) ? get_upper_offset() : 0;

  printf("Verifying flash contents...");

  while(*prom_data != NULL){
    parse_mcs_record(*prom_data, &parsed_record);

    switch(parsed_record.record_type){

      case MCS_PROM_DATA_RECORD:
        if( check_mcs_data_record(&parsed_record, _base_address, regs) != 0 )
          return -1;
        break;

      case MCS_PROM_EXT_LIN_ADDR_RECORD:
        _base_address = (parsed_record.payload[0] << 24) + (parsed_record.payload[1] << 16);
        _base_address |= (upper) ? get_upper_offset() : 0;
        putchar('.');
        fflush(stdout);
        break;

      case MCS_PROM_EOF_RECORD:
        goto done;

      default:
        printf("ERROR: Unknown MCS record type\n");
        return -1;
    }
    prom_data++;
  }

done:
  printf("done\nThe new firmware will take effect after the next system reboot.\n");
  return 0;

}

void single_word_write(unsigned long addr, unsigned int data, exanic_t *regs)
{
  unsigned long sr;

  clear_status_register(regs);
  single_cycle_write(addr, PROGRAM_SETUP, regs);
  single_cycle_write(addr, data, regs);

  /* Wait for PEC status to revert to 'ready' */
  while( ((sr = single_cycle_async_read(addr & BLOCK_ADDRESS_MASK, regs)) & PEC_STATUS_MASK) == 0 );

  if ( (sr & PROGRAM_STATUS_MASK) != 0)
    printf("ERROR: Programming error (SR: 0x%lx)\n", sr);

  if ( (sr & BLOCK_PROTECT_STATUS_MASK) != 0)
    printf("ERROR: Attempted to program a locked block (SR: 0x%lx)\n", sr);

}

void clear_status_register(exanic_t *regs)
{
  single_cycle_write(0, CLEAR_STATUS_REG, regs);
}

void clear_status_register_addr(unsigned long addr, exanic_t *regs)
{
  single_cycle_write(addr, CLEAR_STATUS_REG, regs);
}

/*
 * Use this function when the flash is in a write mode, such that
 * reads to an address result in the status register being returned
 * and issuing the 'read status register' command is not required
 */
unsigned long read_status_register(unsigned long addr, exanic_t *regs)
{
  return (single_cycle_async_read(addr & FLASH_ADDR_BUS_MASK, regs));
}

inline void set_read_reg_mode(unsigned long addr, exanic_t *regs)
{
  single_cycle_write(addr & FLASH_ADDR_BUS_MASK, READ_STATUS_REG, regs);
}

unsigned long query_id_register(unsigned long addr, int offset, exanic_t *regs)
{
  return (single_cycle_async_read((addr & BLOCK_ADDRESS_MASK) + offset, regs));
}

/* returns -1 in case parse of error, 0 otherwise */
int parse_mcs_record16(char *mcs_record, mcs_record_t *parsed_record)
{
  char tmp[5];
  int word_count;
  int payload_characters, i;

  if(mcs_record == NULL){
    return -1;
  }

  if(mcs_record[0] != ':'){
    printf("ERROR: mcs_record[0] != ':'\n");
    return -1;
  }

  tmp[0] = mcs_record[1];
  tmp[1] = mcs_record[2];
  tmp[2] = '\0';

  parsed_record->byte_count = (int)strtol(tmp, NULL, 16);

  tmp[0] = mcs_record[3];
  tmp[1] = mcs_record[4];
  tmp[2] = mcs_record[5];
  tmp[3] = mcs_record[6];
  tmp[4] = '\0';

  parsed_record->address = (int)strtol(tmp, NULL, 16);

  tmp[0] = mcs_record[7];
  tmp[1] = mcs_record[8];
  tmp[2] = '\0';

  parsed_record->record_type = (int)strtol(tmp, NULL, 16);

  word_count = parsed_record->byte_count/2;
  tmp[4] = '\0';

  for(i = 0; i < word_count; i++){

    /* don't swap bytes within a word */
    tmp[2] = mcs_record[9 + 4*i + 0];
    tmp[3] = mcs_record[9 + 4*i + 1];
    tmp[0] = mcs_record[9 + 4*i + 2];
    tmp[1] = mcs_record[9 + 4*i + 3];

    parsed_record->payload[i] = (unsigned int)strtol(tmp, NULL, 16);

  }

  payload_characters = 2 * parsed_record->byte_count;

  tmp[2] = '\0';
  tmp[0] = mcs_record[9 + payload_characters];
  tmp[1] = mcs_record[9 + payload_characters + 1];

  parsed_record->checksum = (int)strtol(tmp, NULL, 16);

  return 0;

}

/* returns -1 in case parse of error, 0 otherwise */
int parse_mcs_record(char *mcs_record, mcs_record_t *parsed_record)
{
  char tmp[5];
  int payload_characters, i;

  if(mcs_record == NULL){
    return -1;
  }

  if(mcs_record[0] != ':'){
    printf("ERROR: mcs_record[0] != ':'\n");
    return -1;
  }

  tmp[0] = mcs_record[1];
  tmp[1] = mcs_record[2];
  tmp[2] = '\0';

  parsed_record->byte_count = (int)strtol(tmp, NULL, 16);

  tmp[0] = mcs_record[3];
  tmp[1] = mcs_record[4];
  tmp[2] = mcs_record[5];
  tmp[3] = mcs_record[6];
  tmp[4] = '\0';

  parsed_record->address = (int)strtol(tmp, NULL, 16);

  tmp[0] = mcs_record[7];
  tmp[1] = mcs_record[8];
  tmp[2] = '\0';

  parsed_record->record_type = (int)strtol(tmp, NULL, 16);

  tmp[2] = '\0';
  for(i = 0; i < parsed_record->byte_count; i++){
    tmp[0] = mcs_record[9 + 2*i];
    tmp[1] = mcs_record[9 + 2*i + 1];
    parsed_record->payload[i] = (int)strtol(tmp, NULL, 16);
  }

  payload_characters = 2 * parsed_record->byte_count;

  tmp[0] = mcs_record[9 + payload_characters];
  tmp[1] = mcs_record[9 + payload_characters + 1];

  parsed_record->checksum = (int)strtol(tmp, NULL, 16);

  return 0;

}

/* Starting addresses in the MCS file seem to refer to 8-bit locations...*/
unsigned long address_adjust(unsigned long mcs_address)
{
  mcs_address |= (upper) ? get_upper_offset() : 0;
  return (mcs_address >> 1);
}

/* returns the number of lines written
 * zero lines written indicates an error */
int burst_write(char **prom_data, exanic_t *regs,
                unsigned long g_base_address)
{
  int i, j, k;
  unsigned long sr;
  mcs_record_t lines[WORDS_PER_BUFFERED_WRITE/8];

  if(prom_data == NULL)
    return -1;

  /* grab a maximum of WORDS_PER_BUFFERED_WRITE words to perform a buffered write */
  /* There are 8 words per mcs record */
  for(i = 0; i < (WORDS_PER_BUFFERED_WRITE/8); i++){

    if( parse_mcs_record16(*prom_data, (lines+i)) == -1 )
      break;

    if( lines[i].record_type != MCS_PROM_DATA_RECORD )
      break;

    prom_data++;

  }

  /* Perform the burst write */
  if(i > 0){

    clear_status_register(regs);

    // issue the set-up command
    single_cycle_write(address_adjust(lines[0].address + g_base_address),
                       BUFFER_PROGRAM, regs);

    // write the value (word_count -1)
    single_cycle_write(address_adjust(lines[0].address + g_base_address),
                       (i*8)-1, regs);

    // burst the data
    for(j = 0; j < i; j++){

      for(k = 0; k < 8; k++){
        single_cycle_write(address_adjust(lines[j].address + g_base_address) + k, lines[j].payload[k], regs);

      }
    }

    // write the confirmation
    single_cycle_write(address_adjust(lines[0].address + g_base_address),
                                      BUFFER_PROGRAM_CONFRM, regs);

    unsigned long ret = wait_for_device(address_adjust(lines[0].address + g_base_address), regs);

    if(SR_PROG_ERROR_BITS(ret))
    {
      printf("ERROR: Programming error 0x%2lx\n", SR_PROG_ERROR_BITS(ret));
    }
    else if (SR_BLOCK_LOCK_ERR_BIT(ret))
    {
      printf("ERROR: Locked block error\n");
    }

    return i;

  }

  for(j = 0; j < i; j++)
    for(k = 0; k < 8; k++)
      single_cycle_write(address_adjust(lines[j].address + g_base_address) + k, lines[j].payload[k], regs);

  /* write the confirmation */
  single_cycle_write(0xFFFFFF, BUFFER_PROGRAM_CONFRM, regs);

  while( ((sr = read_status_register(address_adjust(lines[0].address + g_base_address), regs)) & PEC_STATUS_MASK) == 0 );

  if( (sr & PROGRAM_STATUS_MASK) == 1 )
    printf("ERROR: Programming error\n");

  if( (sr & VPP_STATUS_MASK) == 1 )
    printf("ERROR: Vpp invalid\n");

  if( (sr & BLOCK_PROTECT_STATUS_MASK) == 1 )
    printf("ERROR: Locked block error\n");

  single_cycle_write(address_adjust(lines[0].address + g_base_address), READ_ARRAY, regs);

  return i;

}

int write_prom_data(char **prom_data, exanic_t *regs)
{
  mcs_record_t parsed_line;
  int lines_written;
  unsigned long g_base_address = 0;

  printf("Programming...");
  fflush(stdout);

  while(*prom_data != NULL){

    if( parse_mcs_record(*prom_data, &parsed_line) == -1 )
    {
      printf("ERROR: Unexpected parse error, bailing\n");
      return -1;
    }

    switch(parsed_line.record_type){

      case MCS_PROM_EXT_LIN_ADDR_RECORD:
        g_base_address = (parsed_line.payload[0] << 24)
            + (parsed_line.payload[1] << 16);
        putchar('.');
        fflush(stdout);
        prom_data++;
        break;

      case MCS_PROM_EOF_RECORD:
        goto done;

      case MCS_PROM_DATA_RECORD:
        if( (lines_written = burst_write(prom_data, regs, g_base_address)) == -1 ){
          printf("ERROR: Unexpected failure in burst_write(), exiting\n");
          return -1;
        }
        prom_data += lines_written;
        break;

      default:
        printf("ERROR: Unexpected record type\n");
        break;

    }
  }
done:
  printf("done\n");
  return 0;
}


char **slurp_prom(char *filename)
{
#define MAX_FW_LINES 1000000
  FILE *fp;
  char **prom_data;
  unsigned int line_len;
  unsigned int buff_used = 0;
  unsigned int buff_alloced = MAX_FW_LINES;
  char *value;
  char tmp[50];

  printf("Loading %s...", filename);
  fflush(stdout);

  fp = fopen(filename, "r");
  if (fp == NULL)
  {
    perror(filename);
    return NULL;
  }

  prom_data = (char **)calloc(sizeof(char *), buff_alloced);
  if (prom_data == NULL)
  {
    printf("ERROR: Memory allocation failed\n");
    fclose(fp);
    return NULL;
  }

  while( fscanf(fp, "%49s", tmp) == 1 ){
    line_len = strlen(tmp);
    value = (char *)calloc((line_len+1), sizeof(char));
    if(value == NULL){
      printf("ERROR: Memory allocation failed\n");
      fclose(fp);
      return NULL;
    }

    strcpy(value, tmp);
    prom_data[buff_used] = value;

    buff_used++;

    if(buff_used == buff_alloced){
      printf("ERROR: File too large\n");
      fclose(fp);
      return NULL;
    }
  }

  fclose(fp);
  printf("done\n");
  return prom_data;

}

long int prom_line_checksum(char *p)
{
  long int csum = 0;
  int i;
  int line_len = strlen(p);
  line_len -= 2; /* remove 2 chars for the C/S */
  char tmp[3];

  tmp[2] = '\0';

  for(i = 0; i < line_len; i += 2){
    tmp[0] = p[i];
    tmp[1] = p[i+1];
    csum += strtol(tmp, 0, 16);
  }

  csum = 0xff - csum;
  csum += 1;
  csum &= 0xff;

  return csum;

}

int check_target_hardware(char *header, exanic_t *regs)
{
  uint32_t hw_id;
  hw_id = exanic_register_read(regs, REG_EXANIC_INDEX(REG_EXANIC_HW_ID));
  if ((strncmp(header, ";exanic_x4,", 11) == 0) && (hw_id == EXANIC_HW_X4))
    return 0;
  if ((strncmp(header, ";exanic_x2,", 11) == 0) && (hw_id == EXANIC_HW_X2))
    return 0;
  if ((strncmp(header, ";exanic_x10,", 12) == 0) && (hw_id == EXANIC_HW_X10))
    return 0;
  if ((strncmp(header, ";exanic_x10_gm,", 15) == 0) && (hw_id == EXANIC_HW_X10_GM))
    return 0;
  if ((strncmp(header, ";exanic_x10_hpt,", 16) == 0) && (hw_id == EXANIC_HW_X10_HPT))
    return 0;
  if ((strncmp(header, ";exanic_x40,", 12) == 0) && (hw_id == EXANIC_HW_X40))
    return 0;
  printf("ERROR: firmware image does not match target hardware\n");
  return -1;
}

int check_prom(char **prom)
{
  unsigned int i = 0;
  long int record_type, byte_count;
  long int line_len, computed_checksum, expected_checksum;
  char *p;
  char tmp[3];

  printf("Validating firmware image...");
  fflush(stdout);

  for (i = 0; (p = prom[i]) != NULL; i++) {

    if ( p[0] == ';' )
      continue;

    if ( p[0] != ':' ){
      printf("ERROR: Invalid start character (%c), line %i, aborting\n", p[0], i);
      return -1;
    }

    line_len = strlen(p);

    if (line_len < 11){
      printf("ERROR: Unexpectedly short record, bailing\n");
      return -1;
    }

    tmp[0] = p[7];
    tmp[1] = p[8];
    tmp[2] = '\0';

    record_type = strtol(tmp, NULL, 16);

    if( (record_type != MCS_PROM_DATA_RECORD) &&
        (record_type != MCS_PROM_EOF_RECORD) &&
        (record_type != MCS_PROM_EXT_LIN_ADDR_RECORD) ){
      printf("ERROR: Unknown record type (%li), bailing\n", record_type);
      return -1;
    }

    tmp[0] = p[1];
    tmp[1] = p[2];
    byte_count = strtol(tmp, NULL, 16);

    if( (record_type == MCS_PROM_EOF_RECORD) &&
        (byte_count != 0) ){
      printf("ERROR: unexpected data found in end-of-file record, bailing\n");
      return -1;
    }

    computed_checksum = prom_line_checksum(p+1);
    expected_checksum = strtol( (p+line_len-2), NULL, 16);

    if( computed_checksum != expected_checksum ){
      printf("ERROR: Checksum failure, line %i; computed 0x%02lx, expected 0x%02lx\n", i, computed_checksum, expected_checksum);
      return -1;
    }
  }

  printf("done\n");
  return 0;

}

const char*
byte_to_binary(int x)
{
    static char b[9];
    b[0] = '\0';

    int z;
    for (z = 256; z > 0; z >>= 1)
    {
        strcat(b, ((x & z) == z) ? "1" : "0");
    }

    return b;
}

unsigned long get_data_dir(void)
{
  return ((exanic_flash_ctrl_reg & DATA_DIR_BIT_MASK) >> DATA_DIR_BIT_POS);
}

void set_data_dir(unsigned long dir, exanic_t *regs)
{
  exanic_flash_ctrl_reg = read_exanic_flash_ctrl_reg(regs);
  if(dir == FPGA_TO_FLASH){
    exanic_flash_ctrl_reg |= DATA_DIR_BIT_MASK;
  } else if(dir == FLASH_TO_FPGA) {
    exanic_flash_ctrl_reg &= ~DATA_DIR_BIT_MASK;
  } else
    return;

  write_exanic_flash_ctrl_reg(exanic_flash_ctrl_reg & EXANIC_FLASH_CTRL_REG_MASK, regs);
  return;

}

/* Clear the specified bit(s) to '0' */
void clear_flash_ctrl_bit(unsigned long mask, exanic_t *regs)
{
  unsigned long tmp = read_exanic_flash_ctrl_reg(regs);
  tmp &= ~mask;
  write_exanic_flash_ctrl_reg( tmp & EXANIC_FLASH_CTRL_REG_MASK, regs);
}

/* Set the specified bit(s) to '1' */
void set_flash_ctrl_bit(unsigned long mask, exanic_t *regs)
{
  unsigned long tmp = read_exanic_flash_ctrl_reg(regs);
  tmp |= mask;
  write_exanic_flash_ctrl_reg( tmp & EXANIC_FLASH_CTRL_REG_MASK, regs);
}

void drive_address(unsigned long addr, exanic_t *regs)
{
  exanic_register_write(regs, EXANIC_FLASH_ADDR_REG_ADDR, addr & FLASH_ADDR_BUS_MASK);
}

unsigned long read_data(exanic_t *regs)
{
  uint32_t value;
  value = exanic_register_read(regs, EXANIC_FLASH_DIN_BUS_ADDR);
  return value & FLASH_DATA_BUS_MASK;
}

void write_data(unsigned long data, exanic_t *regs)
{
  /* drive the output to the dout register*/
  exanic_register_write(regs, EXANIC_FLASH_DOUT_BUS_ADDR, data & FLASH_DATA_BUS_MASK);
}

unsigned long read_exanic_flash_ctrl_reg(exanic_t *regs)
{
  uint32_t value;
  value = exanic_register_read(regs, EXANIC_FLASH_CTRL_REG_ADDR);
  return value;
}

void write_exanic_flash_ctrl_reg(unsigned long value, exanic_t *regs)
{
  exanic_register_write(regs, EXANIC_FLASH_CTRL_REG_ADDR, value);
}

void set_read_mode_async(exanic_t *regs)
{
  const unsigned long CR_async_rd = CR_DEFAULT | ASYC_READ_MODE_MASK;

  /* issue set-up command */
  single_cycle_write(CR_async_rd, SET_CR_SETUP, regs);

  /* issue confirmation command */
  single_cycle_write(CR_async_rd, SET_CR_CONFIRM, regs);
}

void single_cycle_write(unsigned long addr_bus, unsigned long data_bus, exanic_t *regs)
{
  /* Set the data bus direction to FPGA->Flash */
  set_data_dir(FPGA_TO_FLASH, regs);

  set_flash_ctrl_bit(nL, regs);
  set_flash_ctrl_bit(nE, regs);
  set_flash_ctrl_bit(nW, regs);
  set_flash_ctrl_bit(nG, regs);

  /* Drive the address value on to the address bus */
  drive_address(addr_bus, regs);

  /* drive nE (chip enable) low to enable the chip */
  clear_flash_ctrl_bit(nE, regs);

  /* write the command to the data bus */
  write_data(data_bus, regs);

  /* drive nL (latch enable) low */
  clear_flash_ctrl_bit(nL, regs);

  /* drive nL (latch enable) high to latch the address value */
  set_flash_ctrl_bit(nL, regs);

  /* drive nW (write enable) low */
  clear_flash_ctrl_bit(nW, regs);

  /* drive nW (write enable) high to latch the data value */
  set_flash_ctrl_bit(nW, regs);

  /* drive nE (chip enable) high to end the write cycle */
  set_flash_ctrl_bit(nE, regs);
}

unsigned long single_cycle_async_read(unsigned long reg_addr, exanic_t *regs)
{
  unsigned long tmp;

  /* set the data bus direction to Flash->FPGA */
  set_data_dir(FLASH_TO_FPGA, regs);

  /* drive nE high */
  set_flash_ctrl_bit(nE, regs);

  /* drive nL high */
  set_flash_ctrl_bit(nL, regs);

  /* drive nG high */
  set_flash_ctrl_bit(nG, regs);

  /* Drive the address on to the address bus */
  drive_address(reg_addr, regs);

  /* drive nE and nL low */
  clear_flash_ctrl_bit(nE | nL, regs);

  /* drive nG (output enable) low to enable chip outputs */
  clear_flash_ctrl_bit(nG, regs);

  /* drive nL (latch enable) high to latch the address */
  set_flash_ctrl_bit(nL, regs);

  /* Read the data register */
  tmp = read_data(regs);

  /* drive nG (output enable) & nE (chip enable) high to end the cycle */
  set_flash_ctrl_bit(nG | nE, regs);

  return tmp;
}

inline unsigned long wait_for_device(unsigned long addr, exanic_t *regs)
{
  unsigned long sr;
  do
  {
    sr = read_status_register(addr, regs);
  } while (!(sr & PEC_STATUS_MASK));

  return sr;
}

int block_operation(unsigned long addr, exanic_t *regs,
                    unsigned long cmd_code, unsigned long confrm_code)
{
  unsigned long _addr = addr & BLOCK_ADDRESS_MASK;
  clear_status_register(regs);

  // issue the blank check command & confirmation
  single_cycle_write(_addr, cmd_code, regs);
  single_cycle_write(_addr, confrm_code, regs);

  return wait_for_device(_addr, regs);
}

int unlock_block(unsigned long addr, exanic_t *regs)
{
  unsigned long _addr = addr & BLOCK_ADDRESS_MASK;
  return block_operation(_addr, regs, UNLOCK_BLOCK_SETUP, UNLOCK_BLOCK_CONFIRM);
}

int lock_block(unsigned long addr, exanic_t *regs)
{
  unsigned long _addr = addr & BLOCK_ADDRESS_MASK;
  return block_operation(_addr, regs, LOCK_BLOCK_SETUP, LOCK_BLOCK_CONFIRM);
}

int erase_block(unsigned long addr, exanic_t *regs)
{
  unsigned long _addr = addr & BLOCK_ADDRESS_MASK;
  int ret = block_operation(_addr, regs, BLOCK_ERASE_SETUP, BLOCK_ERASE_CONFRM);

  if (ret & ERASE_CHECK_STATUS_MASK)
    printf("ERROR: erase error\n");

  if (ret & BLOCK_PROTECT_STATUS_MASK)
    printf("ERROR: erase error (block locked)\n");

  return ret & (ERASE_CHECK_STATUS_MASK);
}

void range_unlock_and_erase(int init_partn, int fin_partn,
                            int init_blk, int fin_blk, exanic_t *regs)
{
  const unsigned long main_block_addr_jump = 0x10000;
  unsigned long addr = (upper) ? (get_upper_offset()>>1) : 0;
  int p, b;

  printf("Erasing...");
  for(p = init_partn; p <= fin_partn; p++)
  {
    for(b = init_blk; b <= fin_blk; b++)
    {
      unlock_block(addr, regs);

      if(erase_block(addr, regs))
      {
        printf("ERROR: Error erasing partition (p:%i, b:%i)\n", p, b);
      }

      putchar('.');
      fflush(stdout);
      addr += main_block_addr_jump;
    }
  }
  printf("done\n");
}

int verify(exanic_t *regs, char **prom_data)
{
  return verify_download(&prom_data[1], regs);
}

int program(exanic_t *regs, char **prom_data)
{
  if (check_target_hardware(prom_data[0], regs) == -1)
    return 1;
  range_unlock_and_erase(0, 1, 0, get_num_blocks(), regs);
  if (write_prom_data(&prom_data[1], regs) != 0)
    return 1;
  return verify_download(&prom_data[1], regs);
}

char **read_prom_file(char *filename)
{
  char **prom_data;

  prom_data = slurp_prom(filename);
  if (!prom_data)
    return NULL;

  if (check_prom(prom_data) != 0)
    return NULL;

  return prom_data;
}

static struct {
  const char *command;
  int (*fn)(exanic_t *regs, char **prom_data);
  const char *help_text;
} commands[] = {
  { "program",     program,       "program new image and verify (default)" },
  { "verify",      verify,        "verify against supplied file only" }
};

void usage(const char *command)
{
    int i;
    printf("usage: %s [-d device] fw_file [command]\ncommands:\n", command);
    for (i = 0; i < sizeof(commands)/sizeof(commands[0]); i++)
        printf("%16s: %s\n", commands[i].command, commands[i].help_text);
}

int
main(int argc, char *argv[])
{
    char *dev = NULL;
    char *command;
    char *fw_file;
    char **prom_data;
    exanic_t *exanic_regs;
    int c, i, ret = 0;

    while ((c = getopt(argc, argv, "rd:h?")) != -1)
    {
        switch (c)
        {
            case 'r':
                upper = 0;
                printf("WARNING: loading recovery image portion of flash\n");
                break;
            case 'd':
                dev = optarg;
                break;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if (argc == optind)
    {
        usage(argv[0]);
        return 1;
    }
    fw_file = argv[optind++];
    if (argc == optind)
        command = "program";
    else
        command = argv[optind];

    if (!dev)
    {
        exanic_regs = exanic_acquire_handle("exanic1");
        if (exanic_regs != NULL)
        {
            exanic_release_handle(exanic_regs);
            printf("Multiple ExaNICs found, please specify which card to update (e.g. -d exanic0)\n");
            return 1;
        }
        dev = "exanic0";
    }

    prom_data = read_prom_file(fw_file);
    if (!prom_data)
        return 1;

    if ((exanic_regs = exanic_acquire_handle(dev)) == NULL)
    {
        printf("%s: %s\n", dev, exanic_get_last_error());
        return 1;
    }

    /* TODO: We need to refactor this utility, but in the mean time... */
    global_hw_id = exanic_register_read(exanic_regs, REG_EXANIC_INDEX(REG_EXANIC_HW_ID));

    set_read_mode_async(exanic_regs);

    for (i = 0; i < sizeof(commands)/sizeof(commands[0]); i++)
    {
        if (!strcmp(command, commands[i].command))
        {
            ret = commands[i].fn(exanic_regs, prom_data);
            break;
        }
    }
    if (i == sizeof(commands)/sizeof(commands[0]))
        printf("%s: unrecognised command\n", command);

    exanic_release_handle(exanic_regs);
    free(prom_data);
    return ret;
}
