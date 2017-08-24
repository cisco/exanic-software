#ifndef EXANIC_Z1_I2C_H
#define EXANIC_Z1_I2C_H

int z1_i2c_sfp_read(exanic_t *exanic, int port_number, uint8_t devaddr,
                    uint8_t regaddr, char *buffer, size_t size);

int z1_i2c_sfp_write(exanic_t *exanic, int port_number, uint8_t devaddr,
                     uint8_t regaddr, char *buffer, size_t size);

#endif /* EXANIC_Z1_I2C_H */
