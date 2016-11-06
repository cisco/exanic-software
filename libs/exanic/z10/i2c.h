#ifndef Z10_I2C_H_3326C93922C539C42B93FDD86591F287
#define Z10_I2C_H_3326C93922C539C42B93FDD86591F287

int z10_i2c_sfp_read(exanic_t *exanic, int port_number, uint8_t devaddr,
                     uint8_t regaddr, char *buffer, size_t size);

int z10_i2c_phy_write(exanic_t *exanic, int port_number, uint8_t regaddr,
                      char *buffer, size_t size);

#endif /* Z10_I2C_H_3326C93922C539C42B93FDD86591F287 */
