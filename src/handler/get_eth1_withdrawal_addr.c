#include "os.h"

#include "io.h"
#include "sw.h"
#include "address.h"
#include "get_eth1_withdrawal_addr.h"

#define PURPOSE   44 | (0x8 << 28)
#define COIN_TYPE 60 | (0x8 << 28)
#define ACCOUNT   0 | (0x8 << 28)
#define CHANGE    0

int handler_get_eth1_withdrawal_addr(uint32_t index) {
    uint32_t path[] = {PURPOSE, COIN_TYPE, ACCOUNT, CHANGE, index};
    uint8_t sk_data[64];
    cx_ecfp_private_key_t sk;
    cx_ecfp_public_key_t pk;
    uint8_t addr[ADDRESS_LEN];
    cx_err_t ret;

    io_seproxyhal_io_heartbeat();
    ret = os_derive_bip32_with_seed_no_throw(HDW_NORMAL,
                                             CX_CURVE_256K1,
                                             path,
                                             ARRAYLEN(path),
                                             sk_data,
                                             NULL,
                                             NULL,
                                             0);
    if (ret == CX_OK) {
        ret = cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, sk_data, 32, &sk);
        memset(sk_data, 0, sizeof(sk_data));
        io_seproxyhal_io_heartbeat();
        if (ret == CX_OK) {
            ret = cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &pk, &sk, 1);
        }
        memset(&sk, 0, sizeof(sk));
    }
    io_seproxyhal_io_heartbeat();
    if ((ret != CX_OK) || !address_from_pubkey(pk.W, addr, sizeof(addr))) {
        return io_send_sw(SW_BAD_STATE);
    }

    buffer_t rdata = {.ptr = addr, .size = sizeof(addr), .offset = 0};

    return io_send_response_buffer(&rdata, SW_OK);
}
