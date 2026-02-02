"""
Модуль для работы с криптографией (RSA, EC, Ethereum)
"""

import hashlib
from typing import Optional, Tuple, List, Union
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.backends import default_backend
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys import keys
from eth_keys.exceptions import BadSignature
from mnemonic import Mnemonic
import secrets


class KeyPair:
    """
    Базовый класс для работы с парами ключей (PEM формат)
    Поддерживает RSA и EC (эллиптические кривые) ключи
    """
    
    def __init__(
        self,
        private_key: Optional[Union[bytes, rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]] = None,
        key_type: Optional[str] = None,
        key_size: Optional[int] = None,
        curve: Optional[ec.EllipticCurve] = None
    ):
        """
        Инициализация пары ключей
        
        Args:
            private_key: 
                - bytes: Приватный ключ в raw формате (для EC) или serialized (для RSA)
                - rsa.RSAPrivateKey: RSA приватный ключ объект
                - ec.EllipticCurvePrivateKey: EC приватный ключ объект
                - None: Генерируется новый ключ
            key_type: Тип ключа ("RSA" или "EC"). Если None, определяется автоматически
            key_size: Размер ключа для RSA (2048, 3072, 4096) или None для EC
            curve: Криптографическая кривая для EC (по умолчанию secp256k1)
        """
        self._key_type = key_type
        self._key_size = key_size
        
        if private_key is None:
            # Генерируем новый ключ
            if key_type == "RSA" or key_size is not None:
                # Генерируем RSA ключ
                if key_size is None:
                    key_size = 2048  # По умолчанию 2048 бит
                self._private_key_obj = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size,
                    backend=default_backend()
                )
                self._key_type = "RSA"
                self._key_size = key_size
            else:
                # Генерируем EC ключ (по умолчанию secp256k1)
                if curve is None:
                    curve = ec.SECP256K1()
                self._private_key_obj = ec.generate_private_key(curve, default_backend())
                self._key_type = "EC"
                self._curve = curve
        elif isinstance(private_key, rsa.RSAPrivateKey):
            # RSA ключ объект
            self._private_key_obj = private_key
            self._key_type = "RSA"
            self._key_size = private_key.key_size
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            # EC ключ объект
            self._private_key_obj = private_key
            self._key_type = "EC"
            self._curve = private_key.curve
        elif isinstance(private_key, bytes):
            # Raw bytes - определяем тип по параметрам или пытаемся как EC
            if key_type == "RSA":
                # Для RSA из bytes нужна десериализация
                raise ValueError("Для RSA ключей из bytes используйте from_pem() или передайте объект ключа")
            else:
                # Предполагаем EC ключ
                if curve is None:
                    curve = ec.SECP256K1()
                if len(private_key) != 32:
                    raise ValueError(f"EC private key must be 32 bytes for secp256k1, got {len(private_key)}")
                self._private_key_obj = ec.derive_private_key(
                    int.from_bytes(private_key, 'big'),
                    curve,
                    default_backend()
                )
                self._key_type = "EC"
                self._curve = curve
                self._private_key_bytes = private_key
        else:
            raise ValueError(f"Unsupported private_key type: {type(private_key)}")
        
        # Получаем публичный ключ
        self._public_key_obj = self._private_key_obj.public_key()
    
    @property
    def key_type(self) -> str:
        """Возвращает тип ключа: 'RSA' или 'EC'"""
        return self._key_type
    
    @property
    def private_key(self) -> bytes:
        """Возвращает приватный ключ в raw формате"""
        if self._key_type == "RSA":
            # Для RSA возвращаем serialized формат
            return self._private_key_obj.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            # Для EC возвращаем raw bytes
            if hasattr(self, '_private_key_bytes'):
                return self._private_key_bytes
            # Для EC ключей получаем raw bytes через private_numbers
            private_value = self._private_key_obj.private_numbers().private_value
            # Преобразуем в bytes (32 байта для secp256k1)
            key_bytes = private_value.to_bytes(32, 'big')
            # Сохраняем для последующих вызовов
            self._private_key_bytes = key_bytes
            return key_bytes
    
    @property
    def public_key(self) -> bytes:
        """Возвращает публичный ключ"""
        if self._key_type == "RSA":
            # Для RSA возвращаем public key в DER формате
            return self._public_key_obj.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:
            # Для EC возвращаем uncompressed формат (без префикса 0x04)
            public_key_bytes = self._public_key_obj.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            return public_key_bytes[1:] if len(public_key_bytes) == 65 else public_key_bytes
    
    @property
    def public_key_compressed(self) -> Optional[bytes]:
        """Возвращает сжатый публичный ключ (только для EC)"""
        if self._key_type != "EC":
            return None
        return self._public_key_obj.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
    
    @property
    def key_size(self) -> Optional[int]:
        """Возвращает размер ключа (для RSA) или None (для EC)"""
        if self._key_type == "RSA":
            return self._key_size
        return None
    
    @property
    def curve(self) -> Optional[ec.EllipticCurve]:
        """Возвращает используемую кривую (только для EC)"""
        if self._key_type == "EC":
            return getattr(self, '_curve', None)
        return None
    
    @classmethod
    def from_private_key(
        cls,
        private_key: Union[bytes, rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        key_type: Optional[str] = None,
        curve: Optional[ec.EllipticCurve] = None
    ) -> "KeyPair":
        """Создает KeyPair из приватного ключа"""
        return cls(private_key, key_type=key_type, curve=curve)
    
    @classmethod
    def from_private_key_hex(
        cls,
        private_key_hex: str,
        key_type: Optional[str] = None,
        curve: Optional[ec.EllipticCurve] = None
    ) -> "KeyPair":
        """Создает KeyPair из приватного ключа в hex формате (только для EC)"""
        if private_key_hex.startswith("0x"):
            private_key_hex = private_key_hex[2:]
        return cls(bytes.fromhex(private_key_hex), key_type=key_type, curve=curve)
    
    @classmethod
    def generate_rsa(cls, key_size: int = 2048) -> "KeyPair":
        """Генерирует новую RSA пару ключей"""
        return cls(key_type="RSA", key_size=key_size)
    
    @classmethod
    def generate_ec(cls, curve: Optional[ec.EllipticCurve] = None) -> "KeyPair":
        """Генерирует новую EC пару ключей"""
        if curve is None:
            curve = ec.SECP256K1()
        return cls(key_type="EC", curve=curve)
    
    @classmethod
    def from_pem(
        cls,
        pem_data: Union[str, bytes],
        password: Optional[bytes] = None,
        key_type: Optional[str] = None
    ) -> "KeyPair":
        """
        Создает KeyPair из PEM формата (PKCS8, PKCS1 для RSA, SEC1 для EC)
        
        Args:
            pem_data: PEM данные (строка или bytes)
            password: Пароль для расшифровки зашифрованного PEM (опционально)
            key_type: Ожидаемый тип ключа ("RSA" или "EC"), если None - определяется автоматически
            
        Returns:
            KeyPair объект
            
        Raises:
            ValueError: Если формат PEM невалиден
        """
        if isinstance(pem_data, str):
            pem_data = pem_data.encode('utf-8')
        
        try:
            private_key = serialization.load_pem_private_key(
                pem_data,
                password=password,
                backend=default_backend()
            )
        except Exception as e:
            raise ValueError(f"Не удалось загрузить PEM ключ: {e}")
        
        # Определяем тип ключа
        if isinstance(private_key, rsa.RSAPrivateKey):
            if key_type and key_type != "RSA":
                raise ValueError(f"Ожидался ключ типа {key_type}, получен RSA")
            return cls(private_key, key_type="RSA")
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            if key_type and key_type != "EC":
                raise ValueError(f"Ожидался ключ типа {key_type}, получен EC")
            return cls(private_key, key_type="EC")
        else:
            raise ValueError(f"Неподдерживаемый тип ключа: {type(private_key)}")
    
    @classmethod
    def from_pem_file(
        cls,
        filepath: Union[str, Path],
        password: Optional[bytes] = None,
        key_type: Optional[str] = None
    ) -> "KeyPair":
        """
        Создает KeyPair из PEM файла
        
        Args:
            filepath: Путь к PEM файлу
            password: Пароль для расшифровки (опционально)
            key_type: Ожидаемый тип ключа (опционально)
            
        Returns:
            KeyPair объект
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"PEM файл не найден: {filepath}")
        
        with open(filepath, 'rb') as f:
            pem_data = f.read()
        
        return cls.from_pem(pem_data, password, key_type)
    
    def to_pem(
        self,
        format: str = "PKCS8",
        password: Optional[bytes] = None,
        encryption_algorithm: Optional[serialization.KeySerializationEncryption] = None
    ) -> bytes:
        """
        Экспортирует приватный ключ в PEM формат
        
        Args:
            format: Формат экспорта:
                   - "PKCS8" - стандартный формат (для RSA и EC)
                   - "PKCS1" - только для RSA
                   - "SEC1" - только для EC
            password: Пароль для шифрования (опционально)
            encryption_algorithm: Алгоритм шифрования (если не указан, используется BestAvailable)
            
        Returns:
            PEM данные в виде bytes
        """
        # Определяем формат
        if self._key_type == "RSA":
            if format.upper() == "PKCS8":
                key_format = serialization.PrivateFormat.PKCS8
            elif format.upper() == "PKCS1":
                key_format = serialization.PrivateFormat.PKCS1
            else:
                raise ValueError(f"Для RSA поддерживаются форматы 'PKCS8' и 'PKCS1', получен: {format}")
        else:  # EC
            if format.upper() == "PKCS8":
                key_format = serialization.PrivateFormat.PKCS8
            elif format.upper() == "SEC1":
                key_format = serialization.PrivateFormat.Raw
            else:
                raise ValueError(f"Для EC поддерживаются форматы 'PKCS8' и 'SEC1', получен: {format}")
        
        # Определяем алгоритм шифрования
        if password:
            if encryption_algorithm is None:
                encryption_algorithm = serialization.BestAvailableEncryption(password)
        else:
            encryption_algorithm = serialization.NoEncryption()
        
        return self._private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=key_format,
            encryption_algorithm=encryption_algorithm
        )
    
    def to_pem_file(
        self,
        filepath: Union[str, Path],
        format: str = "PKCS8",
        password: Optional[bytes] = None
    ):
        """
        Сохраняет приватный ключ в PEM файл
        
        Args:
            filepath: Путь для сохранения файла
            format: Формат экспорта
            password: Пароль для шифрования (опционально)
        """
        filepath = Path(filepath)
        pem_data = self.to_pem(format=format, password=password)
        
        with open(filepath, 'wb') as f:
            f.write(pem_data)
    
    def to_public_pem(self) -> bytes:
        """
        Экспортирует публичный ключ в PEM формат
        
        Returns:
            PEM данные публичного ключа в виде bytes
        """
        return self._public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def to_dict(self) -> dict:
        """Возвращает словарь с ключами"""
        result = {
            "key_type": self.key_type,
            "private_key": self.private_key.hex(),
            "public_key": self.public_key.hex()
        }
        
        if self.key_type == "RSA":
            result["key_size"] = self.key_size
        else:
            result["curve"] = str(self.curve)
        
        return result


class EthKeyPair(KeyPair):
    """
    Класс для работы с Ethereum ключами (наследник KeyPair)
    Добавляет Ethereum-специфичные методы и функциональность
    """
    
    def __init__(self, private_key: Optional[bytes] = None, **ignore):
        """
        Инициализация Ethereum пары ключей
        
        Args:
            private_key: Приватный ключ (32 байта). Если None, генерируется новый.
        """
        # Всегда используем secp256k1 для Ethereum
        super().__init__(private_key, key_type="EC", curve=ec.SECP256K1())
        
        # Сохраняем raw bytes для Ethereum операций
        if private_key is None:
            self._private_key_bytes = self.private_key
        else:
            self._private_key_bytes = private_key
        
        # Инициализируем Ethereum-специфичные объекты
        self._eth_private_key = keys.PrivateKey(self._private_key_bytes)
        self._eth_public_key = self._eth_private_key.public_key
        self._account = Account.from_key(self._private_key_bytes)
    
    @property
    def public_key(self) -> bytes:
        """Возвращает публичный ключ (64 байта, без префикса)"""
        return self._eth_public_key.to_bytes()
    
    @property
    def public_key_compressed(self) -> bytes:
        """Возвращает сжатый публичный ключ (33 байта)"""
        return self._eth_public_key.to_compressed_bytes()
    
    @property
    def address(self) -> str:
        """Возвращает Ethereum адрес"""
        return self._account.address
    
    @classmethod
    def from_private_key(cls, private_key: bytes) -> "EthKeyPair":
        """Создает EthKeyPair из приватного ключа"""
        return cls(private_key)
    
    @classmethod
    def from_private_key_hex(cls, private_key_hex: str) -> "EthKeyPair":
        """Создает EthKeyPair из приватного ключа в hex формате"""
        if private_key_hex.startswith("0x"):
            private_key_hex = private_key_hex[2:]
        return cls(bytes.fromhex(private_key_hex))
    
    @classmethod
    def from_pem(
        cls,
        pem_data: Union[str, bytes],
        password: Optional[bytes] = None
    ) -> "EthKeyPair":
        """Создает EthKeyPair из PEM формата (только secp256k1)"""
        key_pair = super().from_pem(pem_data, password, key_type="EC")
        if not isinstance(key_pair.curve, ec.SECP256K1):
            raise ValueError("PEM должен содержать secp256k1 ключ для Ethereum")
        return cls(key_pair.private_key)
    
    @classmethod
    def from_pem_file(
        cls,
        filepath: Union[str, Path],
        password: Optional[bytes] = None
    ) -> "EthKeyPair":
        """Создает EthKeyPair из PEM файла"""
        key_pair = super().from_pem_file(filepath, password, key_type="EC")
        if not isinstance(key_pair.curve, ec.SECP256K1):
            raise ValueError("PEM должен содержать secp256k1 ключ для Ethereum")
        return cls(key_pair.private_key)
    
    @classmethod
    def from_mnemonic(
        cls,
        mnemonic_phrase: str,
        derivation_path: str = "m/44'/60'/0'/0/0",
        passphrase: str = ""
    ) -> "EthKeyPair":
        """
        Создает EthKeyPair из мнемонической фразы (BIP39)
        
        Args:
            mnemonic_phrase: Мнемоническая фраза (12 или 24 слова)
            derivation_path: BIP44 путь деривации (по умолчанию для Ethereum)
            passphrase: Дополнительная фраза-пароль (опционально)
            
        Returns:
            EthKeyPair объект
            
        Raises:
            ValueError: Если мнемоническая фраза невалидна
        """
        # Проверяем валидность мнемонической фразы
        mnemo = Mnemonic("english")
        if not mnemo.check(mnemonic_phrase):
            raise ValueError("Невалидная мнемоническая фраза")
        
        # Используем eth_account для деривации ключа по BIP44
        try:
            account = Account.from_mnemonic(
                mnemonic_phrase,
                account_path=derivation_path,
                passphrase=passphrase
            )
            return cls(account.key)
        except Exception as e:
            raise ValueError(f"Ошибка при деривации ключа из мнемонической фразы: {e}")
    
    @classmethod
    def from_mnemonic_index(
        cls,
        mnemonic_phrase: str,
        account_index: int = 0,
        change: int = 0,
        address_index: int = 0,
        passphrase: str = ""
    ) -> "EthKeyPair":
        """
        Создает EthKeyPair из мнемонической фразы с указанным индексом аккаунта
        
        Args:
            mnemonic_phrase: Мнемоническая фраза
            account_index: Индекс аккаунта (по умолчанию 0)
            change: Change индекс (0 для внешних, 1 для внутренних адресов)
            address_index: Индекс адреса
            passphrase: Дополнительная фраза-пароль
            
        Returns:
            EthKeyPair объект
        """
        derivation_path = f"m/44'/60'/{account_index}'/{change}/{address_index}"
        return cls.from_mnemonic(mnemonic_phrase, derivation_path, passphrase)
    
    def to_dict(self) -> dict:
        """Возвращает словарь с ключами"""
        return {
            "private_key": self.private_key.hex(),
            "public_key": self.public_key.hex(),
            "address": self.address
        }


class EthCrypto:
    """Класс для криптографических операций с Ethereum"""
    
    @staticmethod
    def generate_mnemonic(strength: int = 128, language: str = "english") -> str:
        """
        Генерирует новую мнемоническую фразу (BIP39)
        
        Args:
            strength: Длина энтропии в битах (128, 160, 192, 224, 256)
                     128 = 12 слов, 256 = 24 слова
            language: Язык для мнемонической фразы (по умолчанию "english")
            
        Returns:
            Мнемоническая фраза
            
        Raises:
            ValueError: Если strength невалиден
        """
        valid_strengths = [128, 160, 192, 224, 256]
        if strength not in valid_strengths:
            raise ValueError(
                f"Strength должен быть одним из: {valid_strengths}. "
                f"Получено: {strength}"
            )
        
        mnemo = Mnemonic(language)
        return mnemo.generate(strength=strength)
    
    @staticmethod
    def validate_mnemonic(mnemonic_phrase: str, language: str = "english") -> bool:
        """
        Проверяет валидность мнемонической фразы
        
        Args:
            mnemonic_phrase: Мнемоническая фраза для проверки
            language: Язык мнемонической фразы
            
        Returns:
            True если фраза валидна, False иначе
        """
        try:
            mnemo = Mnemonic(language)
            return mnemo.check(mnemonic_phrase)
        except Exception:
            return False
    
    @staticmethod
    def mnemonic_to_seed(mnemonic_phrase: str, passphrase: str = "") -> bytes:
        """
        Преобразует мнемоническую фразу в seed (BIP39)
        
        Args:
            mnemonic_phrase: Мнемоническая фраза
            passphrase: Дополнительная фраза-пароль
            
        Returns:
            Seed в виде bytes (64 байта)
            
        Raises:
            ValueError: Если мнемоническая фраза невалидна
        """
        mnemo = Mnemonic("english")
        if not mnemo.check(mnemonic_phrase):
            raise ValueError("Невалидная мнемоническая фраза")
        
        return mnemo.to_seed(mnemonic_phrase, passphrase=passphrase)
    
    @staticmethod
    def generate_accounts_from_mnemonic(
        mnemonic_phrase: str,
        count: int = 5,
        account_index: int = 0,
        change: int = 0,
        passphrase: str = ""
    ) -> List[dict]:
        """
        Генерирует несколько аккаунтов из одной мнемонической фразы
        
        Args:
            mnemonic_phrase: Мнемоническая фраза
            count: Количество аккаунтов для генерации
            account_index: Начальный индекс аккаунта
            change: Change индекс (0 для внешних адресов)
            passphrase: Дополнительная фраза-пароль
            
        Returns:
            Список словарей с информацией об аккаунтах
        """
        accounts = []
        
        for i in range(count):
            derivation_path = f"m/44'/60'/{account_index}'/{change}/{i}"
            try:
                account = Account.from_mnemonic(
                    mnemonic_phrase,
                    account_path=derivation_path,
                    passphrase=passphrase
                )
                key_pair = EthKeyPair(account.key)
                accounts.append({
                    "index": i,
                    "address": key_pair.address,
                    "public_key": key_pair.public_key.hex(),
                    "private_key": key_pair.private_key.hex(),
                    "derivation_path": derivation_path
                })
            except Exception as e:
                # Пропускаем аккаунты с ошибками
                continue
        
        return accounts
    
    @staticmethod
    def sign(message: bytes, private_key: bytes) -> bytes:
        """
        Подписывает сообщение используя ECDSA
        
        Args:
            message: Сообщение для подписи
            private_key: Приватный ключ (32 байта)
            
        Returns:
            Подпись (65 байт: r + s + v)
        """
        if len(private_key) != 32:
            raise ValueError("Private key must be 32 bytes")
        
        account = Account.from_key(private_key)
        message_hash = encode_defunct(message)
        signed_message = account.sign_message(message_hash)
        
        # Возвращаем подпись в формате r + s + v (65 байт)
        return signed_message.signature
    
    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Проверяет подпись сообщения
        
        Args:
            message: Оригинальное сообщение
            signature: Подпись (65 байт: r + s + v)
            public_key: Публичный ключ (64 байта без префикса или 33 байта сжатый)
            
        Returns:
            True если подпись валидна, False иначе
        """
        try:
            if len(signature) != 65:
                return False
            
            # Кодируем сообщение
            message_hash = encode_defunct(message)
            
            # Восстанавливаем адрес из подписи
            recovered_address = Account.recover_message(message_hash, signature=signature)
            
            # Получаем адрес из публичного ключа
            if len(public_key) == 64:
                pub_key_obj = keys.PublicKey.from_bytes(public_key)
            elif len(public_key) == 33:
                pub_key_obj = keys.PublicKey.from_compressed_bytes(public_key)
            else:
                return False
            
            # Вычисляем адрес из публичного ключа
            expected_address = pub_key_obj.to_address()
            
            # Сравниваем адреса (без учета регистра)
            return recovered_address.lower() == expected_address.lower()
        except Exception as e:
            # Если произошла ошибка, возвращаем False
            return False
    
    @staticmethod
    def recover_public_key(message: bytes, signature: bytes) -> Optional[bytes]:
        """
        Восстанавливает публичный ключ из подписи
        
        Args:
            message: Оригинальное сообщение
            signature: Подпись (65 байт)
            
        Returns:
            Публичный ключ (64 байта) или None если не удалось восстановить
        """
        try:
            if len(signature) != 65:
                return None
            
            message_hash = encode_defunct(message)
            
            # Восстанавливаем через eth_keys
            sig = keys.Signature(signature_bytes=signature[:64], v=signature[64])
            
            # Пробуем восстановить публичный ключ из хеша сообщения
            try:
                recovered_pub_key = sig.recover_public_key_from_msg_hash(message_hash.body)
                return recovered_pub_key.to_bytes()
            except AttributeError:
                # Если метод не доступен, используем альтернативный подход
                # Восстанавливаем адрес и пытаемся получить ключ другим способом
                recovered_address = Account.recover_message(message_hash, signature=signature)
                # Для полного восстановления ключа нужен более сложный подход
                # Возвращаем None, так как полное восстановление требует дополнительной логики
                return None
        except Exception:
            return None
    
    @staticmethod
    def derive_key(material: bytes, info: bytes = b"") -> bytes:
        """
        Выводит ключ из материала (для использования в шифровании)
        
        Args:
            material: Исходный материал
            info: Дополнительная информация
            
        Returns:
            Производный ключ (32 байта)
        """
        # Используем HKDF-подобный подход
        hmac_key = hashlib.sha256(material + info).digest()
        return hashlib.sha256(hmac_key + b"didcomm-key").digest()[:32]
    
    @staticmethod
    def encrypt_symmetric(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Симметричное шифрование (упрощенная версия, в продакшене использовать AES-GCM)
        
        Args:
            plaintext: Открытый текст
            key: Ключ шифрования (32 байта)
            
        Returns:
            Кортеж (ciphertext, iv, tag)
        """
        # Для демонстрации используем простой XOR (в продакшене нужен AES-GCM)
        # В реальной реализации нужно использовать cryptography библиотеку
        iv = secrets.token_bytes(16)
        # Упрощенная реализация - в продакшене использовать AES-GCM
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        
        return ciphertext, iv, tag
    
    @staticmethod
    def decrypt_symmetric(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """
        Симметричное дешифрование
        
        Args:
            ciphertext: Зашифрованный текст
            key: Ключ дешифрования (32 байта)
            iv: Вектор инициализации
            tag: Тег аутентификации
            
        Returns:
            Расшифрованный текст
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext


class RsaCrypto:
    """Класс для криптографических операций с RSA"""
    
    @staticmethod
    def sign(message: bytes, private_key_obj: rsa.RSAPrivateKey) -> bytes:
        """
        Подписывает сообщение используя RSA
        
        Args:
            message: Сообщение для подписи
            private_key_obj: RSA приватный ключ объект
            
        Returns:
            Подпись в виде bytes
        """
        signature = private_key_obj.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: Union[bytes, rsa.RSAPublicKey]) -> bool:
        """
        Проверяет подпись сообщения
        
        Args:
            message: Оригинальное сообщение
            signature: Подпись
            public_key: RSA публичный ключ (bytes в DER формате или объект rsa.RSAPublicKey)
            
        Returns:
            True если подпись валидна, False иначе
        """
        try:
            # Если передан bytes, создаем объект ключа
            if isinstance(public_key, bytes):
                public_key_obj = serialization.load_der_public_key(public_key, backend=default_backend())
                if not isinstance(public_key_obj, rsa.RSAPublicKey):
                    return False
            else:
                public_key_obj = public_key
            
            public_key_obj.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def derive_key(material: bytes, info: bytes = b"") -> bytes:
        """
        Выводит ключ из материала (для использования в шифровании)
        
        Args:
            material: Исходный материал
            info: Дополнительная информация
            
        Returns:
            Производный ключ (32 байта)
        """
        # Используем HKDF-подобный подход
        hmac_key = hashlib.sha256(material + info).digest()
        return hashlib.sha256(hmac_key + b"didcomm-key").digest()[:32]
    
    @staticmethod
    def encrypt_symmetric(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Симметричное шифрование
        
        Args:
            plaintext: Открытый текст
            key: Ключ шифрования (32 байта)
            
        Returns:
            Кортеж (ciphertext, iv, tag)
        """
        iv = secrets.token_bytes(16)
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        
        return ciphertext, iv, tag
    
    @staticmethod
    def decrypt_symmetric(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """
        Симметричное дешифрование
        
        Args:
            ciphertext: Зашифрованный текст
            key: Ключ дешифрования (32 байта)
            iv: Вектор инициализации
            tag: Тег аутентификации
            
        Returns:
            Расшифрованный текст
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext


class EcCrypto:
    """Класс для криптографических операций с EC (эллиптическими кривыми)"""
    
    @staticmethod
    def sign(message: bytes, private_key_obj: ec.EllipticCurvePrivateKey) -> bytes:
        """
        Подписывает сообщение используя ECDSA
        
        Args:
            message: Сообщение для подписи
            private_key_obj: EC приватный ключ объект
            
        Returns:
            Подпись в виде bytes
        """
        signature = private_key_obj.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return signature
    
    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: Union[bytes, ec.EllipticCurvePublicKey], curve: Optional[ec.EllipticCurve] = None) -> bool:
        """
        Проверяет подпись сообщения
        
        Args:
            message: Оригинальное сообщение
            signature: Подпись
            public_key: EC публичный ключ (bytes в uncompressed формате или объект ec.EllipticCurvePublicKey)
            curve: Кривая для восстановления ключа из bytes (по умолчанию SECP256K1)
            
        Returns:
            True если подпись валидна, False иначе
        """
        try:
            # Если передан bytes, создаем объект ключа
            if isinstance(public_key, bytes):
                if curve is None:
                    curve = ec.SECP256K1()
                
                # Публичный ключ может быть в разных форматах
                # Пробуем uncompressed (64 байта без префикса или 65 с префиксом 0x04)
                if len(public_key) == 64:
                    # Добавляем префикс 0x04 для uncompressed формата
                    public_key_with_prefix = b'\x04' + public_key
                elif len(public_key) == 65 and public_key[0] == 0x04:
                    public_key_with_prefix = public_key
                elif len(public_key) == 33:
                    # Compressed формат
                    public_key_with_prefix = public_key
                else:
                    return False
                
                try:
                    public_key_obj = ec.EllipticCurvePublicKey.from_encoded_point(
                        curve, public_key_with_prefix
                    )
                except Exception:
                    # Пробуем через DER формат
                    try:
                        public_key_obj = serialization.load_der_public_key(
                            public_key, backend=default_backend()
                        )
                        if not isinstance(public_key_obj, ec.EllipticCurvePublicKey):
                            return False
                    except Exception:
                        return False
            else:
                public_key_obj = public_key
            
            public_key_obj.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def derive_key(material: bytes, info: bytes = b"") -> bytes:
        """
        Выводит ключ из материала (для использования в шифровании)
        
        Args:
            material: Исходный материал
            info: Дополнительная информация
            
        Returns:
            Производный ключ (32 байта)
        """
        # Используем HKDF-подобный подход
        hmac_key = hashlib.sha256(material + info).digest()
        return hashlib.sha256(hmac_key + b"didcomm-key").digest()[:32]
    
    @staticmethod
    def encrypt_symmetric(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Симметричное шифрование
        
        Args:
            plaintext: Открытый текст
            key: Ключ шифрования (32 байта)
            
        Returns:
            Кортеж (ciphertext, iv, tag)
        """
        iv = secrets.token_bytes(16)
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        
        return ciphertext, iv, tag
    
    @staticmethod
    def decrypt_symmetric(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """
        Симметричное дешифрование
        
        Args:
            ciphertext: Зашифрованный текст
            key: Ключ дешифрования (32 байта)
            iv: Вектор инициализации
            tag: Тег аутентификации
            
        Returns:
            Расшифрованный текст
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
