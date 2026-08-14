#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ca2_process(const uint8_t *data, size_t size) {
    char source[64];
    char destination[8];
    if (data == NULL || size >= sizeof(source)) {
        return 0;
    }
    memcpy(source, data, size);
    source[size] = '\0';
    strcpy(destination, source);
    return (unsigned char)destination[0];
}

#ifdef CA2_STANDALONE
int main(int argc, char **argv) {
    uint8_t buffer[64];
    size_t size;
    FILE *handle;
    if (argc != 2) {
        return 64;
    }
    handle = fopen(argv[1], "rb");
    if (handle == NULL) {
        return 66;
    }
    size = fread(buffer, 1, sizeof(buffer), handle);
    fclose(handle);
    return ca2_process(buffer, size) & 0x7f;
}
#endif
