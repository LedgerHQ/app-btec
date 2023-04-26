#include <string.h>

#include "ox_bls.h"

#include "sign.h"
#include "bls_common.h"
#include "io.h"
#include "sw.h"

int handler_sign(uint32_t index, uint8_t *signing_root) {
    const uint8_t dst[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    cx_ecfp_384_private_key_t sk;
    uint32_t path[] = {PURPOSE, COIN_TYPE, index, 0};
    uint8_t hash[192];
    uint8_t sig[96];

    cx_hash_to_field(signing_root, SIGNING_ROOT_SIZE, dst, sizeof(dst) - 1, hash, sizeof(hash));
    get_bls_sk(path, ARRAYLEN(path), &sk);
    ox_bls12381_sign(&sk, hash, sizeof(hash), sig, sizeof(sig));
    memset(&sk, 0, sizeof(sk));
    buffer_t rdata = {.ptr = sig, .size = sizeof(sig), .offset = 0};

    return io_send_response_buffer(&rdata, SW_OK);
}
