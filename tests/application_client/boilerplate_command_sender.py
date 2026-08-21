import struct
from enum import IntEnum
from typing import Generator, List, Optional
from contextlib import contextmanager

from ragger.backend.interface import BackendInterface, RAPDU
from ragger.bip import pack_derivation_path


MAX_APDU_LEN: int = 255

CLA: int = 0xE0

class InsType(IntEnum):
    GET_VERSION              = 0x03
    GET_APP_NAME             = 0x04
    GET_WITHDRAWAL_PK        = 0x05
    GET_SIGNING_PK           = 0x06
    GET_ETH1_WITHDRAWAL_ADDR = 0x07
    SIGN                     = 0x08

class Errors(IntEnum):
    SW_DENY                    = 0x6985
    SW_WRONG_P1P2              = 0x6A86
    SW_WRONG_DATA_LENGTH       = 0x6A87
    SW_INS_NOT_SUPPORTED       = 0x6D00
    SW_CLA_NOT_SUPPORTED       = 0x6E00
    SW_WRONG_RESPONSE_LENGTH   = 0xB000
    SW_DISPLAY_BIP32_PATH_FAIL = 0xB001
    SW_DISPLAY_ADDRESS_FAIL    = 0xB002
    SW_DISPLAY_AMOUNT_FAIL     = 0xB003
    SW_WRONG_TX_LENGTH         = 0xB004
    SW_TX_PARSING_FAIL         = 0xB005
    SW_TX_HASH_FAIL            = 0xB006
    SW_BAD_STATE               = 0xB007
    SW_SIGNATURE_FAIL          = 0xB008


def split_message(message: bytes, max_size: int) -> List[bytes]:
    return [message[x:x + max_size] for x in range(0, len(message), max_size)]


class BoilerplateCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend


    def get_app_and_version(self) -> RAPDU:
        return self.backend.exchange(cla=0xB0,  # specific CLA for BOLOS
                                     ins=0x01,  # specific INS for get_app_and_version
                                     p1=0x00,
                                     p2=0x00,
                                     data=b"")


    def get_version(self) -> RAPDU:
        return self.backend.exchange(cla=CLA,
                                     ins=InsType.GET_VERSION,
                                     p1=0x00,
                                     p2=0x00,
                                     data=b"")


    def get_app_name(self) -> RAPDU:
        return self.backend.exchange(cla=CLA,
                                     ins=InsType.GET_APP_NAME,
                                     p1=0x00,
                                     p2=0x00,
                                     data=b"")


    def get_signing_pk(self, index: int) -> RAPDU:
        return self.backend.exchange(cla=CLA,
                                     ins=InsType.GET_SIGNING_PK,
                                     p1=0x00,
                                     p2=0x00,
                                     data=struct.pack(">I", index))


    def get_withdrawal_pk(self, index: int) -> RAPDU:
        return self.backend.exchange(cla=CLA,
                                     ins=InsType.GET_WITHDRAWAL_PK,
                                     p1=0x00,
                                     p2=0x00,
                                     data=struct.pack(">I", index))


    def get_eth1_withdrawal_addr(self, index: int) -> RAPDU:
        return self.backend.exchange(cla=CLA,
                                     ins=InsType.GET_ETH1_WITHDRAWAL_ADDR,
                                     p1=0x00,
                                     p2=0x00,
                                     data=struct.pack(">I", index))


    @contextmanager
    def sign(self, index: int, signing_root: bytes) -> Generator[None, None, None]:
        with self.backend.exchange_async(cla=CLA,
                                         ins=InsType.SIGN,
                                         p1=0x00,
                                         p2=0x00,
                                         data=struct.pack(">I", index) + signing_root) as response:
            yield response


    def get_async_response(self) -> Optional[RAPDU]:
        return self.backend.last_async_response
