import pickle

from copy import deepcopy
from typing import Any, Dict, List

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def _parse_index_fields(index: str) -> List[str]:
    """ Return all fields that are needed to create a joint index. """
    return index.split("|")


rsa_key = None


def _detenc_bellare07(msg: bytes) -> bytes:
    global rsa_key
    if not rsa_key:
        with open("detenc.pem") as rsa_keyfile:
            rsa_key = RSA.importKey(rsa_keyfile.read())

        rsa_key._randfunc = lambda n: b"0" * n

    cipher = PKCS1_OAEP.new(rsa_key)

    ciphertext = cipher.encrypt(msg)

    return ciphertext


def _get_encrypted_index_for_fields(record: Dict[str, Any], fnames: List[str]) -> bytes:
    fields = {k: v for (k, v) in record.items() if k in fnames}
    serialized_fields = pickle.dumps(fields)
    return _detenc_bellare07(serialized_fields)


def add_encrypted_refs_to_record(
    record: Dict[str, Any], indices: List[str]
) -> Dict[str, Any]:
    """ Given a Tahoe record, modify it so that it contains encrypted index references. """
    record = deepcopy(record)

    encrefs = []

    for index in indices:
        field_names = _parse_index_fields(index)
        encrefs.append(_get_encrypted_index_for_fields(record, field_names))

    record["_encref"] = encrefs

    return record
