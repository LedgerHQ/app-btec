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
    uint8_t sk_data[32];
    cx_ecfp_private_key_t sk;
    cx_ecfp_public_key_t pk;
    uint8_t addr[ADDRESS_LEN];

    io_seproxyhal_io_heartbeat();
    os_perso_derive_node_bip32(CX_CURVE_256K1, path, ARRAYLEN(path), sk_data, NULL);
    cx_ecfp_init_private_key(CX_CURVE_256K1, sk_data, 32, &sk);
    memset(sk_data, 0, sizeof(sk_data));
    io_seproxyhal_io_heartbeat();
    cx_ecfp_generate_pair(CX_CURVE_256K1, &pk, &sk, 1);
    memset(&sk, 0, sizeof(sk));
    io_seproxyhal_io_heartbeat();

    address_from_pubkey(pk.W, addr, sizeof(addr));
    buffer_t rdata = {.ptr = addr, .size = sizeof(addr), .offset = 0};

    return io_send_response_buffer(&rdata, SW_OK);
}
