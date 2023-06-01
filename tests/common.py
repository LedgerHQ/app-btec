from staking_deposit.key_handling.key_derivation.path import mnemonic_and_path_to_key
from ragger.bip.seed import SPECULOS_MNEMONIC
from pathlib import Path

TESTS_ROOT_DIR = Path(__file__).parent
WITHDRAWAL_PATH = "m/12381/3600/%u/0"
SIGNING_PATH = WITHDRAWAL_PATH + "/0"
TEST_LOOPS = 16

def get_bls_sk(path: str) -> bytes:
    return mnemonic_and_path_to_key(SPECULOS_MNEMONIC, path)
