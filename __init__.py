"""
DIDComm пакет для работы с децентрализованной идентичностью и сообщениями
с использованием криптографии Ethereum (secp256k1, ECDSA)
"""

from didcomm.crypto import EthCrypto, KeyPair as BaseKeyPair, EthKeyPair
from didcomm.did import DID, create_peer_did, resolve_did
from didcomm.message import DIDCommMessage, pack_message, unpack_message
from didcomm.resolver import DIDResolver

# Для обратной совместимости: KeyPair указывает на EthKeyPair
KeyPair = EthKeyPair

__version__ = "1.0.0"
__all__ = [
    "EthCrypto",
    "KeyPair",
    "BaseKeyPair",
    "EthKeyPair",
    "DID",
    "create_peer_did",
    "resolve_did",
    "DIDCommMessage",
    "pack_message",
    "unpack_message",
    "DIDResolver",
]

