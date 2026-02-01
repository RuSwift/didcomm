"""
Тесты для RSA ключей: создание, подпись и проверка подписи
"""

import sys
import unittest
from pathlib import Path

# Добавляем родительскую директорию в путь для импорта
parent_dir = Path(__file__).parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Импортируем из родительского модуля
import crypto
KeyPair = crypto.KeyPair


class TestRSAKeyPair(unittest.TestCase):
    """Тесты для RSA ключей"""
    
    def test_create_rsa_key(self):
        """Тест создания RSA ключа"""
        # Создаем RSA ключ размером 2048 бит
        rsa_key = KeyPair.generate_rsa(key_size=2048)
        
        # Проверяем тип ключа
        self.assertEqual(rsa_key.key_type, "RSA")
        
        # Проверяем размер ключа
        self.assertEqual(rsa_key.key_size, 2048)
        
        # Проверяем, что приватный и публичный ключи существуют
        self.assertIsNotNone(rsa_key.private_key)
        self.assertIsNotNone(rsa_key.public_key)
        
        # Проверяем, что ключи имеют правильную длину
        # RSA приватный ключ в DER формате обычно больше 1000 байт
        self.assertGreater(len(rsa_key.private_key), 1000)
        # RSA публичный ключ в DER формате обычно около 300 байт
        self.assertGreater(len(rsa_key.public_key), 200)
    
    def test_rsa_sign_and_verify(self):
        """Тест подписи и проверки подписи RSA"""
        # Создаем RSA ключ
        rsa_key = KeyPair.generate_rsa(key_size=2048)
        
        # Сообщение для подписи
        message = b"Hello, RSA signature test!"
        
        # Подписываем сообщение
        # Используем PSS padding и SHA256 для подписи
        signature = rsa_key._private_key_obj.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Проверяем, что подпись создана
        self.assertIsNotNone(signature)
        self.assertGreater(len(signature), 0)
        
        # Проверяем подпись
        try:
            rsa_key._public_key_obj.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            # Если исключение не выброшено, подпись валидна
            signature_valid = True
        except Exception:
            signature_valid = False
        
        self.assertTrue(signature_valid, "RSA подпись должна быть валидной")
    
    def test_rsa_sign_and_verify_pkcs1v15(self):
        """Тест подписи и проверки подписи RSA с PKCS1v15 padding"""
        # Создаем RSA ключ
        rsa_key = KeyPair.generate_rsa(key_size=2048)
        
        # Сообщение для подписи
        message = b"Test message for RSA PKCS1v15"
        
        # Подписываем сообщение с PKCS1v15 padding
        signature = rsa_key._private_key_obj.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Проверяем подпись
        try:
            rsa_key._public_key_obj.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            signature_valid = True
        except Exception:
            signature_valid = False
        
        self.assertTrue(signature_valid, "RSA подпись с PKCS1v15 должна быть валидной")
    
    def test_rsa_invalid_signature(self):
        """Тест проверки невалидной подписи"""
        # Создаем RSA ключ
        rsa_key = KeyPair.generate_rsa(key_size=2048)
        
        # Сообщение для подписи
        message = b"Original message"
        wrong_message = b"Modified message"
        
        # Подписываем оригинальное сообщение
        signature = rsa_key._private_key_obj.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Пытаемся проверить подпись с неправильным сообщением
        with self.assertRaises(Exception):
            rsa_key._public_key_obj.verify(
                signature,
                wrong_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
    
    def test_rsa_key_serialization(self):
        """Тест сериализации и десериализации RSA ключа"""
        # Создаем RSA ключ
        original_key = KeyPair.generate_rsa(key_size=2048)
        
        # Экспортируем в PEM
        pem_data = original_key.to_pem(format="PKCS8")
        self.assertIsNotNone(pem_data)
        self.assertIsInstance(pem_data, bytes)
        
        # Импортируем из PEM
        loaded_key = KeyPair.from_pem(pem_data)
        
        # Проверяем, что ключи совпадают
        self.assertEqual(original_key.key_type, loaded_key.key_type)
        self.assertEqual(original_key.key_size, loaded_key.key_size)
        
        # Проверяем, что можем подписать и проверить с обоими ключами
        message = b"Test serialization"
        
        # Подписываем оригинальным ключом
        signature = original_key._private_key_obj.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Проверяем загруженным ключом
        try:
            loaded_key._public_key_obj.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            signature_valid = True
        except Exception:
            signature_valid = False
        
        self.assertTrue(signature_valid, "Подпись должна быть валидной после сериализации")


if __name__ == '__main__':
    unittest.main()

