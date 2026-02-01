# DIDComm пакет для Ethereum криптографии

Пакет `didcomm` реализует функциональность для работы с децентрализованной идентичностью (DID) и DIDComm сообщениями с использованием криптографии Ethereum (secp256k1, ECDSA).

## Особенности

- **Ethereum криптография**: Использует secp256k1 и ECDSA для подписи и верификации
- **Peer DID**: Создание и управление Peer DID на основе Ethereum ключей
- **DIDComm сообщения**: Подпись, верификация, шифрование и расшифровка сообщений
- **DID Resolver**: Разрешение DID документов

## Установка

```bash
pip install -r requirements.txt
```

## Зависимости

- `eth-account` - Работа с Ethereum аккаунтами
- `eth-keys` - Криптографические операции Ethereum
- `cryptography` - Шифрование (AES-GCM)
- `mnemonic` - Работа с мнемоническими фразами (BIP39)

## Использование

### Создание ключевой пары

```python
from didcomm import KeyPair

# Генерация новой пары ключей
key_pair = KeyPair()
print(f"Address: {key_pair.address}")
print(f"Public Key: {key_pair.public_key.hex()}")

# Создание из существующего приватного ключа
private_key_hex = "0x..."
key_pair = KeyPair.from_private_key_hex(private_key_hex)
```

### Работа с мнемоническими фразами

```python
from didcomm import KeyPair, EthCrypto

# Генерация новой мнемонической фразы (12 слов)
mnemonic = EthCrypto.generate_mnemonic(strength=128)
print(f"Mnemonic: {mnemonic}")

# Генерация 24-словной фразы
mnemonic_24 = EthCrypto.generate_mnemonic(strength=256)

# Проверка валидности мнемонической фразы
is_valid = EthCrypto.validate_mnemonic(mnemonic)
print(f"Valid: {is_valid}")

# Создание KeyPair из мнемонической фразы
key_pair = KeyPair.from_mnemonic(mnemonic)
print(f"Address: {key_pair.address}")

# Создание с кастомным путем деривации (BIP44)
key_pair_custom = KeyPair.from_mnemonic(
    mnemonic,
    derivation_path="m/44'/60'/0'/0/1"
)

# Создание с указанием индексов
key_pair_indexed = KeyPair.from_mnemonic_index(
    mnemonic,
    account_index=0,
    address_index=2
)

# Генерация нескольких аккаунтов из одной фразы
accounts = EthCrypto.generate_accounts_from_mnemonic(mnemonic, count=5)
for acc in accounts:
    print(f"Account {acc['index']}: {acc['address']}")

# Преобразование мнемонической фразы в seed
seed = EthCrypto.mnemonic_to_seed(mnemonic)
print(f"Seed: {seed.hex()[:32]}...")
```

### Создание DID

```python
from didcomm import create_peer_did, KeyPair

# Создаем ключевую пару
key_pair = KeyPair()

# Создаем Peer DID
did = create_peer_did(key_pair)
print(f"DID: {did.did}")
print(f"DID Document: {did.to_json()}")
```

### Работа с DIDComm сообщениями

```python
from didcomm import DIDCommMessage, pack_message, unpack_message, KeyPair

# Создаем ключевые пары для отправителя и получателя
sender_key = KeyPair()
receiver_key = KeyPair()

# Создаем DID для отправителя и получателя
sender_did = create_peer_did(sender_key)
receiver_did = create_peer_did(receiver_key)

# Создаем сообщение
message = DIDCommMessage(
    body={"text": "Hello, DIDComm!"},
    from_did=sender_did.did,
    to=[receiver_did.did]
)

# Упаковываем сообщение (подписываем и шифруем)
packed = pack_message(
    message,
    from_key=sender_key,
    to_public_keys=[receiver_key.public_key],
    encrypt=True
)

# Распаковываем сообщение
unpacked = unpack_message(
    packed,
    recipient_key=receiver_key,
    sender_public_key=sender_key.public_key
)

print(f"Message: {unpacked.body}")
```

### Использование DID Resolver

```python
from didcomm import DIDResolver, create_peer_did, KeyPair

# Создаем резолвер
resolver = DIDResolver()

# Создаем DID
key_pair = KeyPair()
did = create_peer_did(key_pair)

# Регистрируем DID в резолвере
resolver.register_did(did)

# Разрешаем DID
resolved = resolver.resolve(did.did)
if resolved:
    print(f"Resolved DID: {resolved.to_json()}")

# Получаем публичный ключ из DID
public_key = resolver.get_public_key(did.did)
if public_key:
    print(f"Public Key: {public_key.hex()}")
```

### Криптографические операции

```python
from didcomm import EthCrypto, KeyPair

# Создаем ключевую пару
key_pair = KeyPair()

# Подписываем сообщение
message = b"Hello, Ethereum!"
signature = EthCrypto.sign(message, key_pair.private_key)

# Проверяем подпись
is_valid = EthCrypto.verify(message, signature, key_pair.public_key)
print(f"Signature valid: {is_valid}")

# Восстанавливаем публичный ключ из подписи
recovered_key = EthCrypto.recover_public_key(message, signature)
if recovered_key:
    print(f"Recovered key matches: {recovered_key == key_pair.public_key}")
```

## Структура пакета

- `crypto.py` - Криптографические операции (ключи, подписи, шифрование)
- `did.py` - Работа с DID (создание, разрешение)
- `message.py` - DIDComm сообщения (упаковка, распаковка)
- `resolver.py` - Разрешение DID документов
- `utils.py` - Вспомогательные утилиты

## Отличия от peer-did-python

Этот пакет адаптирован для использования криптографии Ethereum:

- Использует **secp256k1** вместо других кривых
- Использует **ECDSA** для подписи (совместим с Ethereum)
- Работает с **Ethereum адресами** и ключами
- Поддерживает **did:ethr** метод (Ethereum DID)

## Примечания

- В продакшене рекомендуется использовать полную реализацию ECDH для согласования ключей
- Peer DID разрешение требует локального хранения DID документов
- Для did:ethr требуется подключение к реестру или блокчейну

## Лицензия

См. основной файл лицензии проекта.

