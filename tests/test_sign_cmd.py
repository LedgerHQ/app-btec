from application_client.boilerplate_command_sender import BoilerplateCommandSender, Errors
from application_client.boilerplate_response_unpacker import unpack_sig
from py_ecc.bls import G2ProofOfPossession as bls
from common import WITHDRAWAL_PATH, TEST_LOOPS, get_bls_sk, TESTS_ROOT_DIR
from ragger.navigator import NavInsID
from ragger.backend import RaisePolicy
import hashlib

def test_sign_refused(backend, navigator):
    index = 0
    client = BoilerplateCommandSender(backend)
    sk = get_bls_sk(WITHDRAWAL_PATH % (index))
    # hash it to make it 32 bytes long
    signing_root = hashlib.sha256(b"Ledger").digest()
    with client.sign(index, signing_root):
        # Disable raising when trying to unpack an error APDU
        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        navigator.navigate([ NavInsID.RIGHT_CLICK ] +       # review
                           [ NavInsID.RIGHT_CLICK ] +       # index
                           [ NavInsID.RIGHT_CLICK ] * 2 +   # signing root
                           [ NavInsID.RIGHT_CLICK ] +       # approve
                           [ NavInsID.BOTH_CLICK ])         # reject
    assert client.get_async_response().status == Errors.SW_DENY


def notest_sign(backend, navigator):
    client = BoilerplateCommandSender(backend)
    for index in range(TEST_LOOPS):
        sk = get_bls_sk(WITHDRAWAL_PATH % (index))
        # hash it to make it 32 bytes long
        signing_root = hashlib.sha256(b"Ledger %u" % (index)).digest()
        with client.sign(index, signing_root):
            navigator.navigate_and_compare(TESTS_ROOT_DIR,
                                           "sign_%u" % (index),
                                           [ NavInsID.RIGHT_CLICK ] +       # review
                                           [ NavInsID.RIGHT_CLICK ] +       # index
                                           [ NavInsID.RIGHT_CLICK ] * 2 +   # signing root
                                           [ NavInsID.BOTH_CLICK ])         # approve
        sig = unpack_sig(client.get_async_response().data)
        assert sig == bls.Sign(sk, signing_root)
