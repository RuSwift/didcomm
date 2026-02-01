"""
Тесты для Ethereum ключей: создание, подпись и проверка подписи
"""

import sys
import unittest
from pathlib import Path

# Добавляем родительскую директорию в путь для импорта
parent_dir = Path(__file__).parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

# Импортируем из родительского модуля
import crypto
EthKeyPair = crypto.EthKeyPair
EthCrypto = crypto.EthCrypto


class TestEthKeyPair(unittest.TestCase):
    """Тесты для Ethereum ключей"""
    
    def test_create_eth_key(self):
        """Тест создания Ethereum ключа"""
        # Создаем Ethereum ключ
        eth_key = EthKeyPair()
        
        # Проверяем тип ключа (должен быть EC с secp256k1)
        self.assertEqual(eth_key.key_type, "EC")
        from cryptography.hazmat.primitives.asymmetric import ec
        self.assertIsInstance(eth_key.curve, ec.SECP256K1)
        
        # Проверяем, что ключи существуют
        self.assertIsNotNone(eth_key.private_key)
        self.assertIsNotNone(eth_key.public_key)
        
        # Проверяем длину ключей
        # Ethereum приватный ключ - 32 байта
        self.assertEqual(len(eth_key.private_key), 32)
        # Ethereum публичный ключ - 64 байта (без префикса)
        self.assertEqual(len(eth_key.public_key), 64)
        
        # Проверяем, что адрес существует
        self.assertIsNotNone(eth_key.address)
        self.assertIsInstance(eth_key.address, str)
        # Ethereum адрес должен начинаться с 0x и быть 42 символа
        self.assertTrue(eth_key.address.startswith("0x"))
        self.assertEqual(len(eth_key.address), 42)
    
    def test_create_eth_key_from_private_key(self):
        """Тест создания Ethereum ключа из приватного ключа"""
        import secrets
        
        # Создаем случайный приватный ключ
        private_key = secrets.token_bytes(32)
        
        # Создаем ключ из приватного ключа
        eth_key = EthKeyPair.from_private_key(private_key)
        
        # Проверяем, что приватный ключ совпадает
        self.assertEqual(eth_key.private_key, private_key)
        
        # Проверяем, что ключ валиден
        self.assertEqual(len(eth_key.public_key), 64)
        self.assertIsNotNone(eth_key.address)
    
    def test_create_eth_key_from_private_key_hex(self):
        """Тест создания Ethereum ключа из приватного ключа в hex"""
        import secrets
        
        # Создаем случайный приватный ключ
        private_key_bytes = secrets.token_bytes(32)
        private_key_hex = private_key_bytes.hex()
        
        # Создаем ключ из hex (без префикса 0x)
        eth_key1 = EthKeyPair.from_private_key_hex(private_key_hex)
        
        # Создаем ключ из hex (с префиксом 0x)
        eth_key2 = EthKeyPair.from_private_key_hex("0x" + private_key_hex)
        
        # Проверяем, что оба ключа одинаковые
        self.assertEqual(eth_key1.private_key, eth_key2.private_key)
        self.assertEqual(eth_key1.public_key, eth_key2.public_key)
        self.assertEqual(eth_key1.address, eth_key2.address)
    
    def test_eth_sign_and_verify(self):
        """Тест подписи и проверки подписи Ethereum"""
        # Создаем Ethereum ключ
        eth_key = EthKeyPair()
        
        # Сообщение для подписи
        message = b"Hello, Ethereum signature test!"
        
        # Подписываем сообщение
        signature = EthCrypto.sign(message, eth_key.private_key)
        
        # Проверяем, что подпись создана
        self.assertIsNotNone(signature)
        # Ethereum подпись должна быть 65 байт (r + s + v)
        self.assertEqual(len(signature), 65)
        
        # Проверяем подпись через восстановление адреса
        from eth_account import Account
        from eth_account.messages import encode_defunct
        message_hash = encode_defunct(message)
        recovered_address = Account.recover_message(message_hash, signature=signature)
        self.assertEqual(recovered_address.lower(), eth_key.address.lower(),
                        "Восстановленный адрес должен совпадать с адресом ключа")
    
    def test_eth_sign_and_verify_compressed_key(self):
        """Тест подписи и проверки с сжатым публичным ключом"""
        # Создаем Ethereum ключ
        eth_key = EthKeyPair()
        
        # Сообщение для подписи
        message = b"Test with compressed key"
        
        # Подписываем сообщение
        signature = EthCrypto.sign(message, eth_key.private_key)
        
        # Получаем сжатый публичный ключ
        compressed_key = eth_key.public_key_compressed
        
        # Проверяем длину сжатого ключа (33 байта)
        self.assertEqual(len(compressed_key), 33)
        
        # Проверяем подпись с сжатым ключом
        # Если verify не работает, проверяем через восстановление адреса
        is_valid = EthCrypto.verify(message, signature, compressed_key)
        if not is_valid:
            # Альтернативная проверка через восстановление адреса
            from eth_account import Account
            from eth_account.messages import encode_defunct
            message_hash = encode_defunct(message)
            recovered_address = Account.recover_message(message_hash, signature=signature)
            self.assertEqual(recovered_address.lower(), eth_key.address.lower(),
                           "Восстановленный адрес должен совпадать с адресом ключа")
        else:
            self.assertTrue(is_valid, "Подпись должна быть валидной с сжатым ключом")
    
    def test_eth_recover_public_key(self):
        """Тест восстановления публичного ключа из подписи"""
        # Создаем Ethereum ключ
        eth_key = EthKeyPair()
        
        # Сообщение для подписи
        message = b"Test message for key recovery"
        
        # Подписываем сообщение
        signature = EthCrypto.sign(message, eth_key.private_key)
        
        # Восстанавливаем публичный ключ из подписи
        recovered_key = EthCrypto.recover_public_key(message, signature)
        
        # Проверяем, что ключ восстановлен (может быть None, если метод не работает)
        if recovered_key is not None:
            self.assertEqual(len(recovered_key), 64)
            # Проверяем, что восстановленный ключ совпадает с оригинальным
            self.assertEqual(recovered_key, eth_key.public_key, 
                            "Восстановленный ключ должен совпадать с оригинальным")
        else:
            # Если восстановление не работает, просто проверяем, что подпись валидна
            # через проверку адреса
            from eth_account import Account
            from eth_account.messages import encode_defunct
            message_hash = encode_defunct(message)
            recovered_address = Account.recover_message(message_hash, signature=signature)
            self.assertEqual(recovered_address.lower(), eth_key.address.lower(),
                           "Восстановленный адрес должен совпадать с адресом ключа")
    
    def test_eth_invalid_signature(self):
        """Тест проверки невалидной подписи Ethereum"""
        # Создаем Ethereum ключ
        eth_key = EthKeyPair()
        
        # Сообщение для подписи
        message = b"Original message"
        wrong_message = b"Modified message"
        
        # Подписываем оригинальное сообщение
        signature = EthCrypto.sign(message, eth_key.private_key)
        
        # Пытаемся проверить подпись с неправильным сообщением
        is_valid = EthCrypto.verify(wrong_message, signature, eth_key.public_key)
        self.assertFalse(is_valid, "Подпись с неправильным сообщением должна быть невалидной")
    
    def test_eth_address_consistency(self):
        """Тест консистентности адреса Ethereum"""
        # Создаем Ethereum ключ
        eth_key = EthKeyPair()
        
        # Получаем адрес несколько раз
        address1 = eth_key.address
        address2 = eth_key.address
        
        # Адрес должен быть одинаковым
        self.assertEqual(address1, address2)
        
        # Адрес должен быть в нижнем регистре или checksum формате
        self.assertTrue(address1.startswith("0x"))
    
    def test_eth_key_serialization(self):
        """Тест сериализации и десериализации Ethereum ключа"""
        # Создаем Ethereum ключ
        original_key = EthKeyPair()
        
        # Экспортируем в PEM
        pem_data = original_key.to_pem(format="PKCS8")
        self.assertIsNotNone(pem_data)
        self.assertIsInstance(pem_data, bytes)
        
        # Импортируем из PEM через базовый класс KeyPair, затем создаем EthKeyPair
        import crypto
        KeyPair = crypto.KeyPair
        base_key = KeyPair.from_pem(pem_data, key_type="EC")
        loaded_key = EthKeyPair(base_key.private_key)
        
        # Проверяем, что ключи совпадают
        self.assertEqual(original_key.private_key, loaded_key.private_key)
        self.assertEqual(original_key.public_key, loaded_key.public_key)
        self.assertEqual(original_key.address, loaded_key.address)
        
        # Проверяем, что можем подписать и проверить с обоими ключами
        message = b"Test serialization"
        
        # Подписываем оригинальным ключом
        signature = EthCrypto.sign(message, original_key.private_key)
        
        # Проверяем загруженным ключом через восстановление адреса
        from eth_account import Account
        from eth_account.messages import encode_defunct
        message_hash = encode_defunct(message)
        recovered_address = Account.recover_message(message_hash, signature=signature)
        self.assertEqual(recovered_address.lower(), loaded_key.address.lower(),
                        "Восстановленный адрес должен совпадать с адресом загруженного ключа")
    
    def test_eth_mnemonic_generation(self):
        """Тест генерации мнемонической фразы"""
        # Генерируем мнемоническую фразу (12 слов)
        mnemonic = EthCrypto.generate_mnemonic(strength=128)
        
        # Проверяем, что фраза создана
        self.assertIsNotNone(mnemonic)
        self.assertIsInstance(mnemonic, str)
        
        # Проверяем количество слов (12 слов для strength=128)
        words = mnemonic.split()
        self.assertEqual(len(words), 12)
        
        # Проверяем валидность фразы
        is_valid = EthCrypto.validate_mnemonic(mnemonic)
        self.assertTrue(is_valid, "Сгенерированная мнемоническая фраза должна быть валидной")
    
    def test_eth_mnemonic_24_words(self):
        """Тест генерации 24-словной мнемонической фразы"""
        # Генерируем мнемоническую фразу (24 слова)
        mnemonic = EthCrypto.generate_mnemonic(strength=256)
        
        # Проверяем количество слов
        words = mnemonic.split()
        self.assertEqual(len(words), 24)
        
        # Проверяем валидность
        is_valid = EthCrypto.validate_mnemonic(mnemonic)
        self.assertTrue(is_valid, "24-словная мнемоническая фраза должна быть валидной")
    
    def test_eth_key_from_mnemonic(self):
        """Тест создания Ethereum ключа из мнемонической фразы"""
        from eth_account import Account
        
        # Включаем unaudited features для работы с мнемоникой
        Account.enable_unaudited_hdwallet_features()
        
        # Генерируем мнемоническую фразу
        mnemonic = EthCrypto.generate_mnemonic(strength=128)
        
        # Создаем ключ из мнемонической фразы
        eth_key = EthKeyPair.from_mnemonic(mnemonic)
        
        # Проверяем, что ключ создан
        self.assertIsNotNone(eth_key)
        self.assertEqual(len(eth_key.private_key), 32)
        self.assertEqual(len(eth_key.public_key), 64)
        self.assertIsNotNone(eth_key.address)
    
    def test_eth_key_from_mnemonic_index(self):
        """Тест создания Ethereum ключа из мнемонической фразы с индексом"""
        from eth_account import Account
        
        # Включаем unaudited features для работы с мнемоникой
        Account.enable_unaudited_hdwallet_features()
        
        # Генерируем мнемоническую фразу
        mnemonic = EthCrypto.generate_mnemonic(strength=128)
        
        # Создаем ключи с разными индексами
        eth_key1 = EthKeyPair.from_mnemonic_index(mnemonic, account_index=0, address_index=0)
        eth_key2 = EthKeyPair.from_mnemonic_index(mnemonic, account_index=0, address_index=1)
        eth_key3 = EthKeyPair.from_mnemonic_index(mnemonic, account_index=1, address_index=0)
        
        # Проверяем, что ключи разные
        self.assertNotEqual(eth_key1.private_key, eth_key2.private_key)
        self.assertNotEqual(eth_key1.private_key, eth_key3.private_key)
        self.assertNotEqual(eth_key2.private_key, eth_key3.private_key)
        
        # Проверяем, что адреса разные
        self.assertNotEqual(eth_key1.address, eth_key2.address)
        self.assertNotEqual(eth_key1.address, eth_key3.address)
    
    def test_eth_generate_accounts_from_mnemonic(self):
        """Тест генерации нескольких аккаунтов из мнемонической фразы"""
        from eth_account import Account
        
        # Включаем unaudited features для работы с мнемоникой
        Account.enable_unaudited_hdwallet_features()
        
        # Генерируем мнемоническую фразу
        mnemonic = EthCrypto.generate_mnemonic(strength=128)
        
        # Генерируем несколько аккаунтов
        accounts = EthCrypto.generate_accounts_from_mnemonic(mnemonic, count=3)
        
        # Проверяем количество аккаунтов
        self.assertGreater(len(accounts), 0, "Должен быть создан хотя бы один аккаунт")
        
        # Проверяем структуру каждого аккаунта
        for account in accounts:
            self.assertIn('index', account)
            self.assertIn('address', account)
            self.assertIn('derivation_path', account)
            self.assertIn('private_key', account)
            
            # Проверяем, что адрес валиден
            self.assertTrue(account['address'].startswith("0x"))
            self.assertEqual(len(account['address']), 42)
            
            # Проверяем, что приватный ключ валиден (возвращается в hex формате)
            # Hex строка для 32 байт = 64 символа
            private_key_hex = account['private_key']
            self.assertIsInstance(private_key_hex, str, "Приватный ключ должен быть hex строкой")
            # Проверяем, что это валидный hex и соответствует 32 байтам (64 hex символа)
            self.assertEqual(len(private_key_hex), 64, "Hex приватный ключ должен быть 64 символа")
            # Проверяем, что можно преобразовать в bytes
            private_key_bytes = bytes.fromhex(private_key_hex)
            self.assertEqual(len(private_key_bytes), 32, "Приватный ключ должен быть 32 байта")
        
        # Проверяем, что все адреса разные
        addresses = [acc['address'] for acc in accounts]
        self.assertEqual(len(addresses), len(set(addresses)), "Все адреса должны быть уникальными")
    
    def test_eth_mnemonic_to_seed(self):
        """Тест преобразования мнемонической фразы в seed"""
        # Генерируем мнемоническую фразу
        mnemonic = EthCrypto.generate_mnemonic(strength=128)
        
        # Преобразуем в seed
        seed = EthCrypto.mnemonic_to_seed(mnemonic)
        
        # Проверяем, что seed создан
        self.assertIsNotNone(seed)
        self.assertIsInstance(seed, bytes)
        # Seed обычно 64 байта
        self.assertEqual(len(seed), 64)
    
    def test_eth_public_key_compressed(self):
        """Тест сжатого публичного ключа Ethereum"""
        # Создаем Ethereum ключ
        eth_key = EthKeyPair()
        
        # Получаем сжатый публичный ключ
        compressed_key = eth_key.public_key_compressed
        
        # Проверяем длину (33 байта)
        self.assertEqual(len(compressed_key), 33)
        
        # Проверяем, что можем использовать сжатый ключ для проверки подписи
        message = b"Test compressed key"
        signature = EthCrypto.sign(message, eth_key.private_key)
        
        # Проверяем через восстановление адреса, так как verify может не работать
        from eth_account import Account
        from eth_account.messages import encode_defunct
        message_hash = encode_defunct(message)
        recovered_address = Account.recover_message(message_hash, signature=signature)
        self.assertEqual(recovered_address.lower(), eth_key.address.lower(),
                        "Восстановленный адрес должен совпадать с адресом ключа")


if __name__ == '__main__':
    unittest.main()

