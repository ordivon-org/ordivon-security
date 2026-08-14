#include <stddef.h>
#include <stdint.h>

int ca2_process(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) {
        return 0;
    }
    volatile uint8_t table[4] = {1, 2, 3, 4};
    return table[data[0] & 7U];
}
