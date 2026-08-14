#include <stddef.h>
#include <stdint.h>

int ca2_process(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)ca2_process(data, size);
    return 0;
}
