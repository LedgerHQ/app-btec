from application_client.boilerplate_command_sender import BoilerplateCommandSender
from application_client.boilerplate_response_unpacker import unpack_eth1_withdrawal_addr
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from common import TEST_LOOPS
import sha3


ADDRESS_LEN = 20

def test_get_eth1_withdrawal_addr(backend):
    client = BoilerplateCommandSender(backend)
    for index in range(TEST_LOOPS):
        path = "m/44'/60'/0'/0/%u" % (index)
        response = client.get_eth1_withdrawal_addr(index).data
        addr = unpack_eth1_withdrawal_addr(response)
        ref_pk, _ = calculate_public_key_and_chaincode(CurveChoice.Secp256k1, path)
        hctx = sha3.keccak_256()
        hctx.update(bytes.fromhex(ref_pk)[1:65])
        assert addr == hctx.digest()[-ADDRESS_LEN:]
