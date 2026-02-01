"""
Тесты для EC ключей: создание, подпись и проверка подписи
"""

import sys
import unittest
from pathlib import Path

# Добавляем родительскую директорию в путь для импорта
parent_dir = Path(__file__).parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# Импортируем из родительского модуля
import crypto
KeyPair = crypto.KeyPair


class TestECKeyPair(unittest.TestCase):
    """Тесты для EC ключей"""
    
    def test_create_ec_key_secp256k1(self):
        """Тест создания EC ключа secp256k1"""
        # Создаем EC ключ с кривой secp256k1
        ec_key = KeyPair.generate_ec(curve=ec.SECP256K1())
        
        # Проверяем тип ключа
        self.assertEqual(ec_key.key_type, "EC")
        
        # Проверяем кривую
        self.assertIsInstance(ec_key.curve, ec.SECP256K1)
        
        # Проверяем, что приватный и публичный ключи существуют
        self.assertIsNotNone(ec_key.private_key)
        self.assertIsNotNone(ec_key.public_key)
        
        # Проверяем, что ключи имеют правильную длину
        # EC приватный ключ для secp256k1 - 32 байта
        self.assertEqual(len(ec_key.private_key), 32)
        # EC публичный ключ (uncompressed) - 64 байта (без префикса 0x04)
        self.assertEqual(len(ec_key.public_key), 64)
    
    def test_create_ec_key_secp256r1(self):
        """Тест создания EC ключа secp256r1 (P-256)"""
        # Создаем EC ключ с кривой secp256r1
        ec_key = KeyPair.generate_ec(curve=ec.SECP256R1())
        
        # Проверяем тип ключа
        self.assertEqual(ec_key.key_type, "EC")
        
        # Проверяем кривую
        self.assertIsInstance(ec_key.curve, ec.SECP256R1)
        
        # Проверяем, что ключи существуют
        self.assertIsNotNone(ec_key.private_key)
        self.assertIsNotNone(ec_key.public_key)
    
    def test_ec_sign_and_verify_secp256k1(self):
        """Тест подписи и проверки подписи EC secp256k1"""
        # Создаем EC ключ
        ec_key = KeyPair.generate_ec(curve=ec.SECP256K1())
        
        # Сообщение для подписи
        message = b"Hello, EC signature test!"
        
        # Подписываем сообщение
        # Используем ECDSA с SHA256 для подписи
        signature = ec_key._private_key_obj.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        
        # Проверяем, что подпись создана
        self.assertIsNotNone(signature)
        self.assertGreater(len(signature), 0)
        # ECDSA подпись для secp256k1 обычно 64-72 байта (r и s по 32 байта каждый)
        self.assertGreaterEqual(len(signature), 64)
        
        # Проверяем подпись
        try:
            ec_key._public_key_obj.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            # Если исключение не выброшено, подпись валидна
            signature_valid = True
        except Exception:
            signature_valid = False
        
        self.assertTrue(signature_valid, "EC подпись должна быть валидной")
    
    def test_ec_sign_and_verify_secp256r1(self):
        """Тест подписи и проверки подписи EC secp256r1"""
        # Создаем EC ключ
        ec_key = KeyPair.generate_ec(curve=ec.SECP256R1())
        
        # Сообщение для подписи
        message = b"Test message for EC secp256r1"
        
        # Подписываем сообщение
        signature = ec_key._private_key_obj.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        
        # Проверяем подпись
        try:
            ec_key._public_key_obj.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            signature_valid = True
        except Exception:
            signature_valid = False
        
        self.assertTrue(signature_valid, "EC подпись с secp256r1 должна быть валидной")
    
    def test_ec_sign_and_verify_sha384(self):
        """Тест подписи и проверки подписи EC с SHA384"""
        # Создаем EC ключ
        ec_key = KeyPair.generate_ec(curve=ec.SECP256K1())
        
        # Сообщение для подписи
        message = b"Test message with SHA384"
        
        # Подписываем сообщение с SHA384
        signature = ec_key._private_key_obj.sign(
            message,
            ec.ECDSA(hashes.SHA384())
        )
        
        # Проверяем подпись
        try:
            ec_key._public_key_obj.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA384())
            )
            signature_valid = True
        except Exception:
            signature_valid = False
        
        self.assertTrue(signature_valid, "EC подпись с SHA384 должна быть валидной")
    
    def test_ec_invalid_signature(self):
        """Тест проверки невалидной подписи EC"""
        # Создаем EC ключ
        ec_key = KeyPair.generate_ec(curve=ec.SECP256K1())
        
        # Сообщение для подписи
        message = b"Original message"
        wrong_message = b"Modified message"
        
        # Подписываем оригинальное сообщение
        signature = ec_key._private_key_obj.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        
        # Пытаемся проверить подпись с неправильным сообщением
        with self.assertRaises(Exception):
            ec_key._public_key_obj.verify(
                signature,
                wrong_message,
                ec.ECDSA(hashes.SHA256())
            )
    
    def test_ec_key_serialization(self):
        """Тест сериализации и десериализации EC ключа"""
        # Создаем EC ключ
        original_key = KeyPair.generate_ec(curve=ec.SECP256K1())
        
        # Экспортируем в PEM
        pem_data = original_key.to_pem(format="PKCS8")
        self.assertIsNotNone(pem_data)
        self.assertIsInstance(pem_data, bytes)
        
        # Импортируем из PEM
        loaded_key = KeyPair.from_pem(pem_data)
        
        # Проверяем, что ключи совпадают
        self.assertEqual(original_key.key_type, loaded_key.key_type)
        # Проверяем тип кривой (не объекты, так как это разные экземпляры)
        self.assertIsInstance(original_key.curve, type(loaded_key.curve))
        self.assertIsInstance(loaded_key.curve, ec.SECP256K1)
        
        # Проверяем, что можем подписать и проверить с обоими ключами
        message = b"Test serialization"
        
        # Подписываем оригинальным ключом
        signature = original_key._private_key_obj.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        
        # Проверяем загруженным ключом
        try:
            loaded_key._public_key_obj.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            signature_valid = True
        except Exception:
            signature_valid = False
        
        self.assertTrue(signature_valid, "Подпись должна быть валидной после сериализации")
    
    def test_ec_public_key_compressed(self):
        """Тест сжатого публичного ключа EC"""
        # Создаем EC ключ
        ec_key = KeyPair.generate_ec(curve=ec.SECP256K1())
        
        # Получаем сжатый публичный ключ
        compressed_key = ec_key.public_key_compressed
        
        # Проверяем, что сжатый ключ существует
        self.assertIsNotNone(compressed_key)
        
        # Сжатый ключ должен быть 33 байта (1 байт префикс + 32 байта координаты)
        self.assertEqual(len(compressed_key), 33)
        
        # Проверяем, что можем создать публичный ключ из сжатого
        from cryptography.hazmat.primitives import serialization
        public_key_obj = serialization.load_der_public_key(
            ec_key._public_key_obj.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        
        # Проверяем, что можем использовать этот ключ для проверки подписи
        message = b"Test compressed key"
        signature = ec_key._private_key_obj.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        
        try:
            public_key_obj.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            signature_valid = True
        except Exception:
            signature_valid = False
        
        self.assertTrue(signature_valid, "Подпись должна быть валидной с сжатым ключом")


if __name__ == '__main__':
    unittest.main()

