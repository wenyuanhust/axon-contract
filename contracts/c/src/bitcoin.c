#define HAVE_CONFIG_H 1
#define USE_EXTERNAL_DEFAULT_CALLBACKS
#include <secp256k1.c>
#include "secp256k1_data_info.h"

#define RECID_INDEX 64
#define PUBKEY_SIZE 33

enum Error {
    OK,
    ERR_ARGS_LENGTH,
    ERR_VERIFY,
    ERR_SECP256K1_ILLEGAL,
    ERR_SECP256K1_ERROR,
    ERR_SECP256K1_PARSE_SIGNATURE,
    ERR_SECP256K1_RECOVER_PUBKEY,
    ERR_SECP256K1_SERIALIZE_PUBKEY
};

void secp256k1_default_illegal_callback_fn(const char* str, void* data) {
  (void)str;
  (void)data;
//   exit(ERR_SECP256K1_ILLEGAL);
}

void secp256k1_default_error_callback_fn(const char* str, void* data) {
  (void)str;
  (void)data;
//   exit(ERR_SECP256K1_ERROR);
}

int main(int argc, const char *argv[]) {
    if (argc != 4) {
        return ERR_ARGS_LENGTH;
    }

    uint8_t *bytes32    = (uint8_t *)argv[0];
    uint8_t *signature  = (uint8_t *)argv[1];
    uint8_t *pubkey     = (uint8_t *)argv[2];
    uint8_t *precompute = (uint8_t *)argv[3];
    
    /* init secp256k1 context */
    secp256k1_context context;

    context.illegal_callback = default_illegal_callback;
    context.error_callback = default_error_callback;

    secp256k1_ecmult_context_init(&context.ecmult_ctx);
    secp256k1_ecmult_gen_context_init(&context.ecmult_gen_ctx);

    /* setup precomputation data */
    secp256k1_ge_storage(*pre_g)[] = (secp256k1_ge_storage(*)[])precompute;
    secp256k1_ge_storage(*pre_g_128)[] =
        (secp256k1_ge_storage(*)[])(&precompute[CKB_SECP256K1_DATA_PRE_SIZE]);
    context.ecmult_ctx.pre_g = pre_g;
    context.ecmult_ctx.pre_g_128 = pre_g_128;

    /* recover signature */
    secp256k1_ecdsa_recoverable_signature ecc_signature;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            &context, &ecc_signature, signature, signature[RECID_INDEX]) == 0) {
        return ERR_SECP256K1_PARSE_SIGNATURE;
    }

    /* recover pubkey */
    secp256k1_pubkey ecc_pubkey;
    if (secp256k1_ecdsa_recover(&context, &ecc_pubkey, &ecc_signature, bytes32) != 1) {
        return ERR_SECP256K1_RECOVER_PUBKEY;
    }

    uint8_t recover_pubkey[PUBKEY_SIZE] = {0};
    size_t pubkey_size = PUBKEY_SIZE;
    if (secp256k1_ec_pubkey_serialize(&context, recover_pubkey, &pubkey_size, &ecc_pubkey,
                                        SECP256K1_EC_COMPRESSED) != 1) {
        return ERR_SECP256K1_SERIALIZE_PUBKEY;
    }

    /* compare two pubkeys */
    if (memcmp(pubkey, recover_pubkey, PUBKEY_SIZE) != 0) {
        return ERR_VERIFY;
    }

    return OK;
}