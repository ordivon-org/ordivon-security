#include <stddef.h>
#include <stdint.h>

int ca2_process(const uint8_t *data, size_t size) {
    if (data == NULL || size < 64) {
        return 0;
    }
    if (data[0] == 'C' && data[63] == '!') {
        int *result = NULL;
        return *result;
    }
    return 0;
}
