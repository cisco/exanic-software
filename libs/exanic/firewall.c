
#include <string.h>

#include "exanic.h"
#include "pcie_if.h"
#include "firewall.h"
#include "port.h"
#include "util.h"

#include "filter/parser.h"
#include "filter/rules.h"

static int check_firewall(exanic_t *exanic)
{
    if (exanic_get_function_id(exanic) != EXANIC_FUNCTION_FIREWALL)
    {
        exanic_err_printf("not a firewall");
        return -1;
    }
    return 0;
}

static int check_filter_slot(exanic_t *exanic, int slot)
{
    if (slot < 0 || slot >= exanic_get_num_firewall_filters(exanic))
    {
        exanic_err_printf("invalid filter slot: %d", slot);
        return -1;
    }
    return 0;
}

static int exanic_set_firewall_filter_raw(exanic_t *exanic, int slot,
                                         const char *pattern,
                                         const char *mask,
                                         uint8_t ctl)
{
    int ctl_index, ctl_shift, i;

    ctl_index = slot / 4;
    ctl_shift = (slot % 4) * 8;

    /* Set control byte to 0 */
    exanic->registers[REG_FIREWALL_INDEX(REG_FIREWALL_FILTER_CONTROL)
        + ctl_index] &= ~(0xFF << ctl_shift);

    /* Load filter */
    for (i = 0; i < 2 * EXANIC_FILTER_NUM_DWORDS; i++)
    {
        exanic->filters[FIREWALL_FILTER_INDEX(slot) + i] =
            ((uint8_t)mask[2 * i]) |
            ((uint8_t)pattern[2 * i] << 8) |
            ((uint8_t)mask[2 * i + 1] << 16) |
            ((uint8_t)pattern[2 * i + 1] << 24);
    }

    /* Set control byte to desired value */
    exanic->registers[REG_FIREWALL_INDEX(REG_FIREWALL_FILTER_CONTROL)
        + ctl_index] |= ctl << ctl_shift;

    return 0;
}

int exanic_get_num_firewall_filters(exanic_t *exanic)
{
    if (check_firewall(exanic) == -1)
        return -1;
    return exanic->registers[REG_FIREWALL_INDEX(REG_FIREWALL_NUM_FILTERS)];
}

exanic_firewall_state_t exanic_get_firewall_state(exanic_t *exanic)
{
    if (check_firewall(exanic) == -1)
        return EXANIC_FIREWALL_DISABLE;
    return exanic->registers[REG_FIREWALL_INDEX(REG_FIREWALL_STATE)];
}

int exanic_get_firewall_capability(exanic_t *exanic)
{
    if (check_firewall(exanic) == -1)
        return 0;
    return exanic->registers[REG_FIREWALL_INDEX(REG_FIREWALL_CAPABLE)];
}

int exanic_set_firewall_state(exanic_t *exanic, exanic_firewall_state_t state)
{
    if (check_firewall(exanic) == -1)
        return -1;
    exanic->registers[REG_FIREWALL_INDEX(REG_FIREWALL_STATE)] = state;
    return 0;
}

int exanic_set_firewall_filter(exanic_t *exanic, int slot, const char *filter)
{
    char pattern[EXANIC_FILTER_SIZE], mask[EXANIC_FILTER_SIZE];
    int drop_rule;

    if (check_firewall(exanic) == -1)
        return -1;
    if (check_filter_slot(exanic, slot) == -1)
        return -1;

    if (exanic_parse_filter_string(filter, pattern, mask, &drop_rule) == -1)
        return -1;
    if (exanic_set_filter_string(exanic->name, slot, filter) == -1)
        return -1;
    return exanic_set_firewall_filter_raw(exanic, slot, pattern, mask,
            EXANIC_FILTER_ENABLE | (drop_rule == 0 ? EXANIC_FILTER_ALLOW : 0));
}

int exanic_get_firewall_filter(exanic_t *exanic, int slot, char *filter,
                              size_t filter_len)
{
    if (check_firewall(exanic) == -1)
        return -1;
    if (check_filter_slot(exanic, slot) == -1)
        return -1;
    return exanic_get_filter_string(exanic->name, slot, filter, filter_len);
}

int exanic_clear_firewall_filter(exanic_t *exanic, int slot)
{
    char zero[EXANIC_FILTER_SIZE];

    if (check_firewall(exanic) == -1)
        return -1;
    if (check_filter_slot(exanic, slot) == -1)
        return -1;
    if (exanic_clear_filter_string(exanic->name, slot) == -1)
        return -1;
    memset(zero, 0, sizeof(zero));
    return exanic_set_firewall_filter_raw(exanic, slot, zero, zero, 0);
}

int exanic_clear_all_firewall_filters(exanic_t *exanic)
{
    int slot, num_slots;
    char zero[EXANIC_FILTER_SIZE];

    if (check_firewall(exanic) == -1)
        return -1;

    memset(zero, 0, sizeof(zero));
    num_slots = exanic_get_num_firewall_filters(exanic);
    for (slot = 0; slot < num_slots; slot++)
    {
        if (exanic_set_firewall_filter_raw(exanic, slot, zero, zero, 0) == -1)
            return -1;
    }

    return exanic_clear_all_filter_strings(exanic->name);
}
