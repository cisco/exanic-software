#ifndef EXANIC_Z10_I2C_H
#define EXANIC_Z10_I2C_H

int z10_i2c_sfp_read(exanic_t *exanic, int port_number, uint8_t devaddr,
                     uint8_t regaddr, char *buffer, size_t size);

int z10_i2c_phy_write(exanic_t *exanic, int port_number, uint8_t regaddr,
                      char *buffer, size_t size);

#endif /* EXANIC_Z10_I2C_H */
