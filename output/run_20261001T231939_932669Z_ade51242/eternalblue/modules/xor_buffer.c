void xor_buffer(uint8_t *data, size_t len, unsigned int key) {
    for (size_t i = 0; i < len; i++) {
        uint8_t key_byte = key & 0xFF;
        data[i] ^= key_byte;
        key = (key >> 8) | ((key & 0xFF) << 24);
    }
}