#include "../exanic.h"
#include "../pcie_if.h"

static void delay(void)
{
    int i;
    for (i = 0; i < 10000; i++)
        asm volatile ("");
}

static void setsda(exanic_t *exanic, int port_number, int val)
{
    if (val)
        exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            &= ~(1 << (Z1_GPIO_DRV_SDA0 + port_number));
    else
        exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            |= (1 << (Z1_GPIO_DRV_SDA0 + port_number));
    delay();
}

static void setscl(exanic_t *exanic, int port_number, int val)
{
    if (val)
        exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            &= ~(1 << (Z1_GPIO_DRV_SCL0 + port_number));
    else
        exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
            |= (1 << (Z1_GPIO_DRV_SCL0 + port_number));
    delay();
}

static int getsda(exanic_t* exanic, int port_number)
{
    return (exanic->registers[REG_HW_INDEX(REG_HW_I2C_GPIO)]
        & (1 << (Z1_GPIO_SDA0 + port_number))) ? 1 : 0;
}

/* Returns 0 if reset times out */
static int i2c_reset(exanic_t *exanic, int port_number)
{
    int count = 0;
    setscl(exanic, port_number, 1);
    setsda(exanic, port_number, 1);
    while (getsda(exanic, port_number) == 0 && count < 100)
    {
        setscl(exanic, port_number, 0);
        setscl(exanic, port_number, 1);
        count++;
    }
    return (count < 100);
}

static void i2c_start(exanic_t *exanic, int port_number)
{
    /* sda, scl are high */
    setsda(exanic, port_number, 0);
    setscl(exanic, port_number, 0);
}

static void i2c_repstart(exanic_t *exanic, int port_number)
{
    /* scl is low */
    setsda(exanic, port_number, 1);
    setscl(exanic, port_number, 1);
    setsda(exanic, port_number, 0);
    setscl(exanic, port_number, 0);
}

static void i2c_stop(exanic_t *exanic, int port_number)
{
    /* scl is low */
    setsda(exanic, port_number, 0);
    setscl(exanic, port_number, 1);
    setsda(exanic, port_number, 1);
}

/* Returns non-zero if ack received, or 0 if the device did not ack */
static int i2c_outb(exanic_t *exanic, int port_number, char data)
{
    int i, nak;

    /* scl is low */
    for (i = 7; i >= 0; i--)
    {
        setsda(exanic, port_number, data & (1 << i));
        setscl(exanic, port_number, 1);
        setscl(exanic, port_number, 0);
    }
    setsda(exanic, port_number, 1);
    setscl(exanic, port_number, 1);

    nak = getsda(exanic, port_number);
    setscl(exanic, port_number, 0);
    /* scl is low */

    return !nak;
}

static char i2c_inb(exanic_t *exanic, int port_number)
{
    int i;
    char data = 0;

    /* scl is low */
    setsda(exanic, port_number, 1);
    for (i = 7; i >= 0; i--)
    {
        setscl(exanic, port_number, 1);
        if (getsda(exanic, port_number))
            data |= (1 << i);
        setscl(exanic, port_number, 0);
    }
    /* scl is low */

    return data;
}

int z1_i2c_sfp_read(exanic_t *exanic, int port_number, uint8_t devaddr,
                    uint8_t regaddr, char *buffer, size_t size)
{
    size_t i;

    if (!i2c_reset(exanic, port_number))
    {
        exanic_err_printf("I2C reset error");
        return -1;
    }
    i2c_start(exanic, port_number);
    if (!i2c_outb(exanic, port_number, devaddr) ||
            !i2c_outb(exanic, port_number, regaddr))
    {
        exanic_err_printf("no ack from device on I2C write");
        return -1;
    }
    for (i = 0; i < size; i++)
    {
        i2c_repstart(exanic, port_number);
        if (!i2c_outb(exanic, port_number, devaddr | 1))
        {
            exanic_err_printf("no ack from device on I2C write");
            return -1;
        }
        buffer[i] = i2c_inb(exanic, port_number);
    }
    i2c_stop(exanic, port_number);

    return 0;
}

int z1_i2c_sfp_write(exanic_t *exanic, int port_number, uint8_t devaddr,
                     uint8_t regaddr, const char *buffer, size_t size)
{
    size_t i;

    if (!i2c_reset(exanic, port_number))
    {
        exanic_err_printf("I2C reset error");
        return -1;
    }
    i2c_start(exanic, port_number);
    if (!i2c_outb(exanic, port_number, devaddr) ||
            !i2c_outb(exanic, port_number, regaddr))
    {
        exanic_err_printf("no ack from device on I2C write");
        return -1;
    }
    for (i = 0; i < size; i++)
    {
        if (!i2c_outb(exanic, port_number, buffer[i]))
        {
            exanic_err_printf("no ack from device on I2C write");
            return -1;
        }
    }
    i2c_stop(exanic, port_number);

    return 0;
}
