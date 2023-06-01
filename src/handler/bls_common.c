#include <string.h>

#include "os_io_seproxyhal.h"
#include "os_seed.h"

#include "bls_common.h"

cx_err_t get_bls_sk(const uint32_t *path, uint8_t path_length, cx_ecfp_384_private_key_t *sk) {
    uint8_t sk_data[48];
    cx_err_t ret;

    memset(sk_data, 0, 16);
    io_seproxyhal_io_heartbeat();
    ret = os_derive_eip2333_no_throw(CX_CURVE_BLS12_381_G1, path, path_length, sk_data + 16);
    io_seproxyhal_io_heartbeat();
    if (ret == CX_OK) {
        ret = cx_ecfp_init_private_key_no_throw(CX_CURVE_BLS12_381_G1,
                                                sk_data,
                                                sizeof(sk_data),
                                                (cx_ecfp_private_key_t *) sk);
    }
    memset(sk_data, 0, sizeof(sk_data));
    return ret;
}
