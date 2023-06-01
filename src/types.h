#pragma once

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_VERSION = 0x03,   /// version of the application
    GET_APP_NAME = 0x04,  /// name of the application
    GET_WITHDRAWAL_PK = 0x05,
    GET_SIGNING_PK = 0x06,
    GET_ETH1_WITHDRAWAL_ADDR = 0x07,
    SIGN = 0x08
} command_e;
