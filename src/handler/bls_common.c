#include <string.h>

#include "os_io_seproxyhal.h"
#include "os_seed.h"

#include "bls_common.h"

void get_bls_sk(const uint32_t *path, uint8_t path_length, cx_ecfp_384_private_key_t *sk) {
    uint8_t sk_data[48];

    memset(sk_data, 0, 16);
    io_seproxyhal_io_heartbeat();
    os_perso_derive_eip2333(CX_CURVE_BLS12_381_G1, path, path_length, sk_data + 16);
    io_seproxyhal_io_heartbeat();
    cx_ecfp_init_private_key(CX_CURVE_BLS12_381_G1,
                             sk_data,
                             sizeof(sk_data),
                             (cx_ecfp_private_key_t *) sk);
    memset(sk_data, 0, sizeof(sk_data));
}
