#ifndef BLS_COMMON_H_
#define BLS_COMMON_H_

#include <stdint.h>
#include "lcx_ecfp.h"

#define PURPOSE   12381
#define COIN_TYPE 3600

cx_err_t get_bls_sk(const uint32_t *path, uint8_t path_length, cx_ecfp_384_private_key_t *sk);

#endif  // BLS_COMMON_H_
