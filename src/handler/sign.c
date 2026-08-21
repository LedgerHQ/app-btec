#include <string.h>

#include "ox_bls.h"

#include "sign.h"
#include "bls_common.h"
#include "io.h"
#include "sw.h"
#include "../ui/display.h"

#pragma GCC diagnostic ignored "-Wformat"  // snprintf

static uint32_t g_index = 0;
static uint8_t *g_signing_root = NULL;

int handler_sign(uint32_t index, uint8_t *signing_root) {
    g_index = index;
    g_signing_root = signing_root;
    snprintf(g_index_str, sizeof(g_index_str), "%u", g_index);
    snprintf(g_signing_root_str,
             sizeof(g_signing_root_str),
             "0x%.*h",
             SIGNING_ROOT_SIZE,
             g_signing_root);
    ui_display_sign();
    return 0;
}

void sign(bool approved) {
    const uint8_t dst[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    cx_ecfp_384_private_key_t sk;
    uint32_t path[] = {PURPOSE, COIN_TYPE, g_index, 0};
    uint8_t hash[192];
    uint8_t sig[96];
    cx_err_t ret;

    if (!approved) {
        io_send_sw(SW_DENY);
        return;
    }
    ret = cx_hash_to_field(g_signing_root,
                           SIGNING_ROOT_SIZE,
                           dst,
                           sizeof(dst) - 1,
                           hash,
                           sizeof(hash));
    if (ret == CX_OK) {
        ret = get_bls_sk(path, ARRAYLEN(path), &sk);
    }
    if (ret == CX_OK) {
        ret = ox_bls12381_sign(&sk, hash, sizeof(hash), sig, sizeof(sig));
    }
    memset(&sk, 0, sizeof(sk));
    if (ret != CX_OK) {
        io_send_sw(SW_BAD_STATE);
    } else {
        buffer_t rdata = {.ptr = sig, .size = sizeof(sig), .offset = 0};

        io_send_response_buffer(&rdata, SW_OK);
    }
}
