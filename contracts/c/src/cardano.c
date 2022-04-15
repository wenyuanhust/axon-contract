#include <ed25519.h>
#include <stdio.h>

#define BLAKE2B_BLOCK_SIZE 32
#define ADDRESS_SIZE 57
#define PUBLIC_KEY_SIZE 32

#define ADDRESS_FILL_OFFSET 27
#define PAYLOAD_FILL_OFFSET (27 + 57 + 3)

enum Error {
    OK,
    ERR_ARGS_LENGTH,
    ERR_VERIFY
};

typedef unsigned char uint8_t;

uint8_t message[119] = {
    // prefix (27 bytes)
    132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 88, 70, 162, 1, 39, 103, 97, 100, 100, 114, 101, 115, 115, 88, 57,
    // be filled for address (57 bytes)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // suffix (3 bytes)
    64, 88, 32,
    // be filled for payload (32 bytes)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

int main(int argc, const char *argv[]) {
    if (argc != 3) {
        return ERR_ARGS_LENGTH;
    }

    uint8_t *digest    = (uint8_t *)argv[0];
    uint8_t *signature = (uint8_t *)argv[1];
    uint8_t *pubkey    = (uint8_t *)argv[2];
    uint8_t *address   = (uint8_t *)argv[2] + PUBLIC_KEY_SIZE;

    memcpy(&message[ADDRESS_FILL_OFFSET], address, ADDRESS_SIZE);
    memcpy(&message[PAYLOAD_FILL_OFFSET], digest, BLAKE2B_BLOCK_SIZE);

    int ok = ed25519_verify(signature, message, sizeof(message), pubkey);
    if (ok != 1) {
        return ERR_VERIFY;
    }

    return OK;
}
