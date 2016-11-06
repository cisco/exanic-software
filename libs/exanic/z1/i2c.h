#ifndef Z1_I2C_H_444319FB44A54F3CA89B95C248BAA2E3
#define Z1_I2C_H_444319FB44A54F3CA89B95C248BAA2E3

int z1_i2c_sfp_read(exanic_t *exanic, int port_number, uint8_t devaddr,
                    uint8_t regaddr, char *buffer, size_t size);

int z1_i2c_sfp_write(exanic_t *exanic, int port_number, uint8_t devaddr,
                     uint8_t regaddr, char *buffer, size_t size);

#endif /* Z1_I2C_H_444319FB44A54F3CA89B95C248BAA2E3 */
