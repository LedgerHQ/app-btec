from application_client.boilerplate_command_sender import BoilerplateCommandSender
from application_client.boilerplate_response_unpacker import unpack_pk
from py_ecc.bls import G2ProofOfPossession as bls
from common import WITHDRAWAL_PATH, SIGNING_PATH, TEST_LOOPS, get_bls_sk

def get_bls_pk(path: str) -> bytes:
    sk = get_bls_sk(path)
    pk = bls.SkToPk(sk)
    return pk

def notest_get_withdrawal_pk(backend):
    client = BoilerplateCommandSender(backend)
    for index in range(TEST_LOOPS):
        response = client.get_withdrawal_pk(index).data
        pk = unpack_pk(response)
        assert pk == get_bls_pk(WITHDRAWAL_PATH % (index))

def notest_get_signing_pk(backend):
    client = BoilerplateCommandSender(backend)
    for index in range(TEST_LOOPS):
        response = client.get_signing_pk(index).data
        pk = unpack_pk(response)
        assert pk == get_bls_pk(SIGNING_PATH % (index))
