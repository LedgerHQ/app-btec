from pathlib import Path
from hashlib import sha256
import functools

from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_der
from Crypto.Hash import keccak


ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()


# Check if a signature of a given message is valid
def check_signature_validity(public_key: bytes, signature: bytes, message: bytes) -> bool:
    pk: VerifyingKey = VerifyingKey.from_string(
        public_key,
        curve=SECP256k1,
        hashfunc=sha256
    )
    return pk.verify(signature=signature,
                     data=message,
                     hashfunc=functools.partial(keccak.new, digest_bits=256),
                     sigdecode=sigdecode_der)
