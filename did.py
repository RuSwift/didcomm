"""
Модуль для работы с DID (Decentralized Identifiers) на основе Ethereum
"""

import json
import hashlib
from typing import Dict, List, Optional, Any, Union
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from .crypto import EthKeyPair, EthCrypto, KeyPair


class DID:
    """Класс для работы с DID документами"""
    
    def __init__(self, did: str, did_document: Optional[Dict] = None):
        """
        Инициализация DID
        
        Args:
            did: DID строка (например, "did:peer:1:...")
            did_document: DID документ (опционально)
        """
        self.did = did
        self.did_document = did_document or {}
    
    def get_verification_methods(self) -> List[Dict]:
        """Возвращает список методов верификации"""
        return self.did_document.get("verificationMethod", [])
    
    def get_authentication_methods(self) -> List[Dict]:
        """Возвращает список методов аутентификации"""
        return self.did_document.get("authentication", [])
    
    def get_key_agreement_methods(self) -> List[Dict]:
        """Возвращает список методов согласования ключей"""
        return self.did_document.get("keyAgreement", [])
    
    def to_dict(self) -> Dict:
        """Возвращает DID документ в виде словаря"""
        return {
            "id": self.did,
            **self.did_document
        }
    
    def to_json(self) -> str:
        """Возвращает DID документ в формате JSON"""
        return json.dumps(self.to_dict(), indent=2)


def create_peer_did(
    key_pair: EthKeyPair,
    service_endpoints: Optional[List[Dict]] = None,
    additional_keys: Optional[List[EthKeyPair]] = None
) -> DID:
    """
    Создает Peer DID на основе Ethereum ключей
    
    Args:
        key_pair: Основная пара ключей
        service_endpoints: Список сервисных эндпоинтов (опционально)
        additional_keys: Дополнительные ключи для keyAgreement (опционально)
        
    Returns:
        DID объект
    """
    # Создаем уникальный идентификатор на основе публичного ключа
    public_key_hash = hashlib.sha256(key_pair.public_key).hexdigest()[:16]
    did = f"did:peer:1:z{public_key_hash}"
    
    # Создаем DID документ
    did_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "EcdsaSecp256k1VerificationKey2019",
                "controller": did,
                "publicKeyHex": key_pair.public_key.hex()
            }
        ],
        "authentication": [
            f"{did}#key-1"
        ],
        "assertionMethod": [
            f"{did}#key-1"
        ]
    }
    
    # Добавляем keyAgreement если есть дополнительные ключи
    if additional_keys:
        key_agreement = []
        for i, key in enumerate(additional_keys, start=2):
            key_id = f"{did}#key-{i}"
            did_document["verificationMethod"].append({
                "id": key_id,
                "type": "X25519KeyAgreementKey2019",  # В реальности нужен X25519 ключ
                "controller": did,
                "publicKeyHex": key.public_key.hex()
            })
            key_agreement.append(key_id)
        did_document["keyAgreement"] = key_agreement
    
    # Добавляем сервисные эндпоинты
    if service_endpoints:
        did_document["service"] = service_endpoints
    
    return DID(did, did_document)


def create_peer_did_from_keypair(
    key_pair: Union[KeyPair, EthKeyPair],
    service_endpoints: Optional[List[Dict]] = None,
    additional_keys: Optional[List[Union[KeyPair, EthKeyPair]]] = None
) -> DID:
    """
    Создает Peer DID на основе любого криптоключа (RSA, EC, Ethereum)
    
    Args:
        key_pair: Пара ключей (KeyPair для RSA/EC или EthKeyPair для Ethereum)
        service_endpoints: Список сервисных эндпоинтов (опционально)
        additional_keys: Дополнительные ключи для keyAgreement (опционально)
        
    Returns:
        DID объект
    """
    # Получаем публичный ключ
    public_key_bytes = key_pair.public_key
    
    # Создаем уникальный идентификатор на основе публичного ключа
    public_key_hash = hashlib.sha256(public_key_bytes).hexdigest()[:16]
    did = f"did:peer:1:z{public_key_hash}"
    
    # Определяем тип ключа и соответствующий verification method
    if isinstance(key_pair, EthKeyPair):
        # Ethereum ключ (secp256k1)
        verification_method_type = "EcdsaSecp256k1VerificationKey2019"
        public_key_format = "publicKeyHex"
        public_key_value = public_key_bytes.hex()
        context = [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        ]
    elif key_pair.key_type == "EC":
        # EC ключ - определяем кривую
        curve = key_pair.curve
        if isinstance(curve, ec.SECP256K1):
            verification_method_type = "EcdsaSecp256k1VerificationKey2019"
            context = [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/secp256k1-2019/v1"
            ]
        elif isinstance(curve, ec.SECP256R1):
            verification_method_type = "EcdsaSecp256r1VerificationKey2019"
            context = [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ecdsa-2019/v1"
            ]
        elif isinstance(curve, ec.SECP384R1):
            verification_method_type = "EcdsaSecp384r1VerificationKey2019"
            context = [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ecdsa-2019/v1"
            ]
        elif isinstance(curve, ec.SECP521R1):
            verification_method_type = "EcdsaSecp521r1VerificationKey2019"
            context = [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ecdsa-2019/v1"
            ]
        else:
            # Общий тип для других EC кривых
            verification_method_type = "JsonWebKey2020"
            context = [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1"
            ]
        
        # Для EC ключей используем hex формат
        public_key_format = "publicKeyHex"
        public_key_value = public_key_bytes.hex()
        
    elif key_pair.key_type == "RSA":
        # RSA ключ
        verification_method_type = "RsaVerificationKey2018"
        # Для RSA используем PEM формат
        public_key_format = "publicKeyPem"
        # Конвертируем в PEM формат
        public_key_pem = key_pair._public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_value = public_key_pem.decode('utf-8')
        context = [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/rsa-2018/v1"
        ]
    else:
        raise ValueError(f"Неподдерживаемый тип ключа: {key_pair.key_type}")
    
    # Создаем verification method
    verification_method = {
        "id": f"{did}#key-1",
        "type": verification_method_type,
        "controller": did,
    }
    
    # Добавляем публичный ключ в правильном формате
    if public_key_format == "publicKeyHex":
        verification_method["publicKeyHex"] = public_key_value
    elif public_key_format == "publicKeyPem":
        verification_method["publicKeyPem"] = public_key_value
    
    # Создаем DID документ
    did_document = {
        "@context": context,
        "id": did,
        "verificationMethod": [verification_method],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"]
    }
    
    # Добавляем keyAgreement если есть дополнительные ключи
    if additional_keys:
        key_agreement = []
        for i, key in enumerate(additional_keys, start=2):
            key_id = f"{did}#key-{i}"
            # Определяем тип для дополнительных ключей
            if isinstance(key, EthKeyPair):
                key_method = {
                    "id": key_id,
                    "type": "X25519KeyAgreementKey2019",  # В реальности нужен X25519
                    "controller": did,
                    "publicKeyHex": key.public_key.hex()
                }
            elif key.key_type == "EC":
                key_method = {
                    "id": key_id,
                    "type": "X25519KeyAgreementKey2019",  # В реальности нужен X25519
                    "controller": did,
                    "publicKeyHex": key.public_key.hex()
                }
            else:
                # Для RSA используем JsonWebKey2020
                key_pem = key._public_key_obj.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                key_method = {
                    "id": key_id,
                    "type": "JsonWebKey2020",
                    "controller": did,
                    "publicKeyPem": key_pem.decode('utf-8')
                }
            did_document["verificationMethod"].append(key_method)
            key_agreement.append(key_id)
        did_document["keyAgreement"] = key_agreement
    
    # Добавляем сервисные эндпоинты
    if service_endpoints:
        did_document["service"] = service_endpoints
    
    return DID(did, did_document)


def resolve_did(did: str) -> Optional[DID]:
    """
    Разрешает DID в DID документ
    
    Args:
        did: DID строка
        
    Returns:
        DID объект или None если не удалось разрешить
    """
    # Для peer DID мы можем разрешить локально на основе идентификатора
    # В реальной реализации это может требовать обращения к реестру
    
    if not did.startswith("did:peer:1:z"):
        return None
    
    # Извлекаем хеш из DID
    did_hash = did.replace("did:peer:1:z", "")
    
    # В реальной реализации здесь должна быть логика разрешения
    # Для peer DID это обычно локальное разрешение на основе хеша
    # Возвращаем None, так как полное разрешение требует хранения DID документов
    
    return None


def create_did_from_address(address: str, public_key: bytes) -> DID:
    """
    Создает DID из Ethereum адреса и публичного ключа
    
    Args:
        address: Ethereum адрес
        public_key: Публичный ключ (64 байта)
        
    Returns:
        DID объект
    """
    # Создаем DID на основе адреса
    did = f"did:ethr:{address.lower()}"
    
    did_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#controller",
                "type": "EcdsaSecp256k1VerificationKey2019",
                "controller": did,
                "publicKeyHex": public_key.hex(),
                "ethereumAddress": address
            }
        ],
        "authentication": [
            f"{did}#controller"
        ],
        "assertionMethod": [
            f"{did}#controller"
        ]
    }
    
    return DID(did, did_document)

