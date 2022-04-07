#include <ed25519.h>

#define BLAKE2B_BLOCK_SIZE 32

enum Error {
    OK,
    ERR_ARGS_LENGTH,
    ERR_VERIFY
};

int main(int argc, const char *argv[]) {
    if (argc != 3) {
        return ERR_ARGS_LENGTH;
    }

    uint8_t *message   = (uint8_t *)argv[0];
    uint8_t *signature = (uint8_t *)argv[1];
    uint8_t *pub_key   = (uint8_t *)argv[2];

    int ok = ed25519_verify(signature, message, BLAKE2B_BLOCK_SIZE, pub_key);
    if (ok != 1) {
        return ERR_VERIFY;
    }

    return OK;
}