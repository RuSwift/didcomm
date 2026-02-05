"""
Модуль для работы с DIDComm сообщениями
"""

import json
import base64
from typing import Dict, Optional, List, Any, Union, Tuple, Type
from datetime import datetime
import uuid
from .crypto import EthKeyPair, EthCrypto, KeyPair, RsaCrypto, EcCrypto
from .did import DID
from cryptography.hazmat.primitives.asymmetric import ec


class DIDCommMessage:
    """Класс для работы с DIDComm сообщениями"""
    
    def __init__(
        self,
        body: Dict[str, Any],
        from_did: Optional[str] = None,
        to: Optional[List[str]] = None,
        id: Optional[str] = None,
        type: Optional[str] = None,
        created_time: Optional[str] = None,
        expires_time: Optional[str] = None,
        thid: Optional[str] = None,
        pthid: Optional[str] = None,
        **kwargs
    ):
        """
        Инициализация DIDComm сообщения
        
        Args:
            body: Тело сообщения
            from_did: DID отправителя
            to: Список DID получателей
            id: Уникальный идентификатор сообщения
            type: Тип сообщения
            created_time: Время создания (ISO 8601)
            expires_time: Время истечения (ISO 8601)
            thid: Thread ID (для связи сообщений)
            pthid: Parent Thread ID (для вложенных потоков)
            **kwargs: Дополнительные поля
        """
        self.id = id or str(uuid.uuid4())
        self.type = type or "https://didcomm.org/basicmessage/1.0/message"
        self.body = body
        self.from_did = from_did
        self.to = to or []
        self.created_time = created_time or datetime.utcnow().isoformat() + "Z"
        self.expires_time = expires_time
        self.thid = thid
        self.pthid = pthid
        # Store any additional fields
        self.extra_fields = kwargs
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразует сообщение в словарь"""
        message = {
            "id": self.id,
            "type": self.type,
            "body": self.body
        }
        
        if self.from_did:
            message["from"] = self.from_did
        
        if self.to:
            message["to"] = self.to
        
        if self.created_time:
            message["created_time"] = self.created_time
        
        if self.expires_time:
            message["expires_time"] = self.expires_time
        
        if self.thid:
            message["thid"] = self.thid
        
        if self.pthid:
            message["pthid"] = self.pthid
        
        # Include any extra fields
        if hasattr(self, 'extra_fields'):
            message.update(self.extra_fields)
        
        return message
    
    def to_json(self) -> str:
        """Преобразует сообщение в JSON строку"""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DIDCommMessage":
        """Создает сообщение из словаря"""
        # Extract known fields
        known_fields = {
            'body', 'from', 'to', 'id', 'type', 
            'created_time', 'expires_time', 'thid', 'pthid'
        }
        
        # Separate extra fields
        extra_fields = {k: v for k, v in data.items() if k not in known_fields}
        
        return cls(
            body=data.get("body", {}),
            from_did=data.get("from"),
            to=data.get("to"),
            id=data.get("id"),
            type=data.get("type"),
            created_time=data.get("created_time"),
            expires_time=data.get("expires_time"),
            thid=data.get("thid"),
            pthid=data.get("pthid"),
            **extra_fields
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> "DIDCommMessage":
        """Создает сообщение из JSON строки"""
        return cls.from_dict(json.loads(json_str))


def pack_message(
    message: DIDCommMessage,
    from_key: Union[EthKeyPair, KeyPair],
    to_public_keys: List[bytes],
    encrypt: bool = True
) -> Dict[str, Any]:
    """
    Упаковывает DIDComm сообщение (подписывает и опционально шифрует)
    
    Args:
        message: DIDComm сообщение
        from_key: Ключ отправителя для подписи (EthKeyPair, KeyPair для RSA или EC)
        to_public_keys: Публичные ключи получателей для шифрования
        encrypt: Шифровать ли сообщение
        
    Returns:
        Упакованное сообщение в формате JWM (JSON Web Message)
    """
    # Сериализуем сообщение
    message_json = message.to_json()
    message_bytes = message_json.encode('utf-8')
    
    # Определяем тип ключа и используем соответствующий криптографический класс
    if isinstance(from_key, EthKeyPair):
        # Ethereum ключ
        signature = EthCrypto.sign(message_bytes, from_key.private_key)
        alg = "ES256K"  # ECDSA secp256k1
        crypto_class = EthCrypto
    elif isinstance(from_key, KeyPair):
        if from_key.key_type == "RSA":
            # RSA ключ
            signature = RsaCrypto.sign(message_bytes, from_key._private_key_obj)
            alg = "RS256"  # RSA with SHA-256
            crypto_class = RsaCrypto
        elif from_key.key_type == "EC":
            # EC ключ
            signature = EcCrypto.sign(message_bytes, from_key._private_key_obj)
            # Определяем алгоритм по кривой
            from cryptography.hazmat.primitives.asymmetric import ec
            if isinstance(from_key.curve, ec.SECP256K1):
                alg = "ES256K"  # ECDSA secp256k1
            elif isinstance(from_key.curve, ec.SECP256R1):
                alg = "ES256"  # ECDSA P-256
            else:
                alg = "ES256"  # По умолчанию
            crypto_class = EcCrypto
        else:
            raise ValueError(f"Неподдерживаемый тип ключа: {from_key.key_type}")
    else:
        raise ValueError(f"Неподдерживаемый тип ключа: {type(from_key)}")
    
    # Создаем JWM структуру
    jwm = {
        "protected": base64.urlsafe_b64encode(
            json.dumps({
                "typ": "application/didcomm-signed+json",
                "alg": alg,
                "kid": f"{message.from_did}#key-1" if message.from_did else None
            }).encode('utf-8')
        ).decode('utf-8').rstrip('='),
        "payload": base64.urlsafe_b64encode(message_bytes).decode('utf-8').rstrip('='),
        "signature": base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
    }
    
    # Если нужно шифровать
    if encrypt and to_public_keys:
        # Генерируем общий секрет для каждого получателя
        # В реальной реализации используется ECDH для согласования ключей
        # Здесь упрощенная версия
        
        # Создаем временный ключ для шифрования (используем EC для ECDH)
        from cryptography.hazmat.primitives.asymmetric import ec
        temp_key = KeyPair.generate_ec(curve=ec.SECP256K1())
        shared_secrets = []
        
        for to_pub_key in to_public_keys:
            # В реальности здесь должен быть ECDH
            # Для упрощения используем производный ключ
            shared_secret = crypto_class.derive_key(
                temp_key.public_key + to_pub_key,
                b"didcomm-encryption"
            )
            shared_secrets.append(shared_secret)
        
        # Шифруем сообщение (используем первый общий секрет)
        # ВАЖНО: Используем sort_keys=True для канонической сериализации JSON
        # Это гарантирует, что порядок ключей будет одинаковым при сериализации и десериализации
        if shared_secrets:
            ciphertext, iv, tag = crypto_class.encrypt_symmetric(
                json.dumps(jwm, sort_keys=True).encode('utf-8'),
                shared_secrets[0]
            )
            
            # Определяем алгоритм для шифрования
            if isinstance(from_key, EthKeyPair) or (isinstance(from_key, KeyPair) and from_key.key_type == "EC"):
                enc_alg = "ECDH-ES+A256KW"
            else:
                enc_alg = "RSA-OAEP-256"  # Для RSA
            
            # Создаем JWE структуру
            # Сохраняем ephemeral public key для восстановления общего секрета при расшифровке
            jwe = {
                "protected": base64.urlsafe_b64encode(
                    json.dumps({
                        "typ": "application/didcomm-encrypted+json",
                        "alg": enc_alg,
                        "enc": "A256GCM",
                        "kid": f"{message.to[0]}#key-1" if message.to else None
                    }).encode('utf-8')
                ).decode('utf-8').rstrip('='),
                "iv": base64.urlsafe_b64encode(iv).decode('utf-8').rstrip('='),
                "ciphertext": base64.urlsafe_b64encode(ciphertext).decode('utf-8').rstrip('='),
                "tag": base64.urlsafe_b64encode(tag).decode('utf-8').rstrip('='),
                "epk": base64.urlsafe_b64encode(temp_key.public_key).decode('utf-8').rstrip('=')
            }
            
            return jwe
    
    return jwm


def unpack_message(
    packed_message: Dict[str, Any],
    recipient_key: Union[EthKeyPair, KeyPair],
    sender_public_key: Optional[bytes] = None,
    sender_key_type: Optional[str] = None
) -> DIDCommMessage:
    """
    Распаковывает DIDComm сообщение (проверяет подпись и расшифровывает)
    
    Args:
        packed_message: Упакованное сообщение
        recipient_key: Ключ получателя для расшифровки (EthKeyPair, KeyPair для RSA или EC)
        sender_public_key: Публичный ключ отправителя для проверки подписи
        sender_key_type: Тип ключа отправителя ("RSA", "EC", "ETH" или None для автоопределения)
        
    Returns:
        Распакованное DIDComm сообщение
    """
    # Определяем криптографический класс для получателя
    if isinstance(recipient_key, EthKeyPair):
        recipient_crypto = EthCrypto
    elif isinstance(recipient_key, KeyPair):
        if recipient_key.key_type == "RSA":
            recipient_crypto = RsaCrypto
        elif recipient_key.key_type == "EC":
            recipient_crypto = EcCrypto
        else:
            raise ValueError(f"Неподдерживаемый тип ключа получателя: {recipient_key.key_type}")
    else:
        raise ValueError(f"Неподдерживаемый тип ключа получателя: {type(recipient_key)}")
    
    # Проверяем тип сообщения
    if "ciphertext" in packed_message:
        # Это зашифрованное сообщение (JWE)
        protected_header = json.loads(
            base64.urlsafe_b64decode(
                packed_message["protected"] + "=="
            ).decode('utf-8')
        )
        
        iv = base64.urlsafe_b64decode(packed_message["iv"] + "==")
        ciphertext = base64.urlsafe_b64decode(packed_message["ciphertext"] + "==")
        tag = base64.urlsafe_b64decode(packed_message["tag"] + "==")
        
        # Восстанавливаем общий секрет (упрощенная версия)
        # В реальности нужен ECDH
        if "epk" in packed_message:
            # Извлекаем ephemeral public key и используем тот же алгоритм, что при шифровании
            temp_public_key = base64.urlsafe_b64decode(packed_message["epk"] + "==")
            shared_secret = recipient_crypto.derive_key(
                temp_public_key + recipient_key.public_key,
                b"didcomm-encryption"
            )
        else:
            # Fallback для старых сообщений (обратная совместимость)
            shared_secret = recipient_crypto.derive_key(
                recipient_key.public_key,
                b"didcomm-encryption"
            )
        
        # Расшифровываем
        decrypted = recipient_crypto.decrypt_symmetric(ciphertext, shared_secret, iv, tag)
        jwm = json.loads(decrypted.decode('utf-8'))
        
        # ВАЖНО: Проверяем подпись СРАЗУ после расшифровки JWM, ДО извлечения payload
        # Base64-строка payload не должна меняться при json.dumps/loads
        if sender_public_key and "signature" in jwm:
            signature_b64 = jwm["signature"]
            # Исправляем padding для signature
            missing_padding = len(signature_b64) % 4
            if missing_padding:
                signature_b64 += '=' * (4 - missing_padding)
            signature = base64.urlsafe_b64decode(signature_b64)
            
            # Извлекаем payload для проверки подписи
            # Payload - это base64-строка, которая не должна меняться при json.dumps/loads
            payload_b64_for_verify = jwm["payload"]
            missing_padding = len(payload_b64_for_verify) % 4
            if missing_padding:
                payload_b64_for_verify += '=' * (4 - missing_padding)
            payload_for_verify = base64.urlsafe_b64decode(payload_b64_for_verify)
            
            # Определяем криптографический класс для отправителя
            sender_crypto, curve = _get_crypto_for_verification(sender_public_key, sender_key_type, jwm.get("protected"))
            
            # Проверяем подпись
            # Payload должен быть идентичен message_bytes, который был подписан при создании
            # Для зашифрованных сообщений payload не должен меняться при json.dumps/loads,
            # так как это base64-строка. Проверяем подпись напрямую.
            if sender_crypto == EcCrypto and curve:
                is_valid = sender_crypto.verify(payload_for_verify, signature, sender_public_key, curve)
            else:
                is_valid = sender_crypto.verify(payload_for_verify, signature, sender_public_key)
            if not is_valid:
                # Если проверка не прошла, это ошибка безопасности
                # Payload должен быть идентичен оригинальному message_bytes
                raise ValueError("Invalid message signature")
    else:
        # Это подписанное сообщение (JWM)
        jwm = packed_message
        
        # Проверяем подпись для незашифрованных сообщений
        if sender_public_key and "signature" in jwm:
            signature_b64 = jwm["signature"]
            # Исправляем padding для signature
            missing_padding = len(signature_b64) % 4
            if missing_padding:
                signature_b64 += '=' * (4 - missing_padding)
            signature = base64.urlsafe_b64decode(signature_b64)
            
            # Извлекаем payload для проверки подписи
            payload_b64_for_verify = jwm["payload"]
            missing_padding = len(payload_b64_for_verify) % 4
            if missing_padding:
                payload_b64_for_verify += '=' * (4 - missing_padding)
            payload_for_verify = base64.urlsafe_b64decode(payload_b64_for_verify)
            
            # Определяем криптографический класс для отправителя
            sender_crypto, curve = _get_crypto_for_verification(sender_public_key, sender_key_type, jwm.get("protected"))
            
            # Проверяем подпись
            if sender_crypto == EcCrypto and curve:
                is_valid = sender_crypto.verify(payload_for_verify, signature, sender_public_key, curve)
            else:
                is_valid = sender_crypto.verify(payload_for_verify, signature, sender_public_key)
            if not is_valid:
                raise ValueError("Invalid message signature")
    
    # Извлекаем payload для использования
    payload_b64 = jwm["payload"]
    # Добавляем padding если нужно
    missing_padding = len(payload_b64) % 4
    if missing_padding:
        payload_b64 += '=' * (4 - missing_padding)
    payload = base64.urlsafe_b64decode(payload_b64)
    message_dict = json.loads(payload.decode('utf-8'))
    
    return DIDCommMessage.from_dict(message_dict)


def _get_crypto_for_verification(
    sender_public_key: bytes,
    sender_key_type: Optional[str],
    protected_header_b64: Optional[str]
) -> Tuple[Union[Type[EthCrypto], Type[RsaCrypto], Type[EcCrypto]], Optional[ec.EllipticCurve]]:
    """
    Определяет криптографический класс для проверки подписи
    
    Args:
        sender_public_key: Публичный ключ отправителя
        sender_key_type: Тип ключа отправителя ("RSA", "EC", "ETH" или None)
        protected_header_b64: Base64-кодированный защищенный заголовок JWM
        
    Returns:
        Кортеж (криптографический класс, кривая для EC или None)
    """
    # Пытаемся определить из заголовка СНАЧАЛА (приоритет)
    if protected_header_b64:
        try:
            missing_padding = len(protected_header_b64) % 4
            if missing_padding:
                protected_header_b64 += '=' * (4 - missing_padding)
            protected_header = json.loads(
                base64.urlsafe_b64decode(protected_header_b64).decode('utf-8')
            )
            alg = protected_header.get("alg", "")
            if alg.startswith("RS"):
                return RsaCrypto, None
            elif alg.startswith("ES"):
                # ES256K - это Ethereum/secp256k1, ES256 - это P-256
                if alg == "ES256K":
                    return EthCrypto, None
                else:
                    # ES256 - это secp256r1 (P-256)
                    return EcCrypto, ec.SECP256R1()
        except Exception:
            pass
    
    # Если тип ключа явно указан и заголовок не помог
    if sender_key_type:
        if sender_key_type.upper() == "RSA":
            return RsaCrypto, None
        elif sender_key_type.upper() == "EC":
            return EcCrypto, ec.SECP256K1()  # По умолчанию secp256k1
        elif sender_key_type.upper() == "ETH":
            return EthCrypto, None
    
    # Пытаемся определить по размеру ключа
    # RSA публичные ключи обычно больше 200 байт
    # EC публичные ключи обычно 64 байта (uncompressed) или 33 байта (compressed)
    # Ethereum публичные ключи обычно 64 байта
    if len(sender_public_key) > 200:
        return RsaCrypto, None
    elif len(sender_public_key) == 64 or len(sender_public_key) == 33:
        # По умолчанию предполагаем EC (не Ethereum, так как для Ethereum нужен EthKeyPair)
        return EcCrypto, ec.SECP256K1()  # По умолчанию secp256k1
    else:
        # По умолчанию используем EC
        return EcCrypto, ec.SECP256K1()

