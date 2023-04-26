/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"
#include "io.h"

#include "dispatcher.h"
#include "../constants.h"
#include "../globals.h"
#include "../types.h"
#include "../sw.h"
#include "../handler/get_version.h"
#include "../handler/get_app_name.h"
#include "../handler/get_pk.h"
#include "../handler/get_eth1_withdrawal_addr.h"
#include "../handler/sign.h"

int apdu_dispatcher(const command_t *cmd) {
    if (cmd->cla != CLA) {
        return io_send_sw(SW_CLA_NOT_SUPPORTED);
    }

    switch (cmd->ins) {
        case GET_VERSION:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            return handler_get_version();

        case GET_APP_NAME:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            return handler_get_app_name();

        case GET_WITHDRAWAL_PK:
            if ((cmd->p1 > 1) || (cmd->p2 > 0)) {
                return io_send_sw(SW_WRONG_P1P2);
            } else if (cmd->lc != sizeof(uint32_t)) {
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            }
            return handler_get_withdrawal_pk(U4BE(cmd->data, 0));

        case GET_SIGNING_PK:
            if ((cmd->p1 > 1) || (cmd->p2 > 0)) {
                return io_send_sw(SW_WRONG_P1P2);
            } else if (cmd->lc != sizeof(uint32_t)) {
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            }
            return handler_get_signing_pk(U4BE(cmd->data, 0));

        case GET_ETH1_WITHDRAWAL_ADDR:
            if ((cmd->p1 > 1) || (cmd->p2 > 0)) {
                return io_send_sw(SW_WRONG_P1P2);
            } else if (cmd->lc != sizeof(uint32_t)) {
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            }
            return handler_get_eth1_withdrawal_addr(U4BE(cmd->data, 0));

        case SIGN:
            if ((cmd->p1 > 1) || (cmd->p2 > 0)) {
                return io_send_sw(SW_WRONG_P1P2);
            } else if (cmd->lc != (sizeof(uint32_t) + SIGNING_ROOT_SIZE)) {
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            }
            return handler_sign(U4BE(cmd->data, 0), cmd->data + sizeof(uint32_t));

        default:
            return io_send_sw(SW_INS_NOT_SUPPORTED);
    }
}
