"""
Модуль для разрешения DID документов
"""

from typing import Optional, Dict
from .did import DID, resolve_did, create_did_from_address
from .crypto import KeyPair


class DIDResolver:
    """Класс для разрешения DID документов"""
    
    def __init__(self):
        """Инициализация резолвера"""
        # В реальной реализации здесь может быть подключение к реестру DID
        self._cache: Dict[str, DID] = {}
    
    def resolve(self, did: str) -> Optional[DID]:
        """
        Разрешает DID в DID документ
        
        Args:
            did: DID строка
            
        Returns:
            DID объект или None если не удалось разрешить
        """
        # Проверяем кеш
        if did in self._cache:
            return self._cache[did]
        
        # Пытаемся разрешить
        resolved = None
        
        if did.startswith("did:peer:1:"):
            # Peer DID - локальное разрешение
            resolved = resolve_did(did)
        elif did.startswith("did:ethr:"):
            # Ethereum DID - разрешение через блокчейн или реестр
            # Извлекаем адрес из DID
            address = did.replace("did:ethr:", "").split("#")[0]
            # В реальной реализации здесь должен быть запрос к реестру
            # Для демонстрации возвращаем None
            resolved = None
        else:
            # Другие методы DID
            resolved = None
        
        # Кешируем результат
        if resolved:
            self._cache[did] = resolved
        
        return resolved
    
    def register_did(self, did: DID):
        """
        Регистрирует DID в локальном кеше
        
        Args:
            did: DID объект для регистрации
        """
        self._cache[did.did] = did
    
    def get_public_key(self, did: str, key_id: Optional[str] = None) -> Optional[bytes]:
        """
        Получает публичный ключ из DID документа
        
        Args:
            did: DID строка
            key_id: ID ключа (опционально, если None берется первый)
            
        Returns:
            Публичный ключ в виде bytes или None
        """
        resolved = self.resolve(did)
        if not resolved:
            return None
        
        verification_methods = resolved.get_verification_methods()
        if not verification_methods:
            return None
        
        # Если указан key_id, ищем его
        if key_id:
            for vm in verification_methods:
                if vm.get("id") == key_id:
                    public_key_hex = vm.get("publicKeyHex")
                    if public_key_hex:
                        return bytes.fromhex(public_key_hex)
            return None
        
        # Иначе берем первый
        public_key_hex = verification_methods[0].get("publicKeyHex")
        if public_key_hex:
            return bytes.fromhex(public_key_hex)
        
        return None
    
    def clear_cache(self):
        """Очищает кеш резолвера"""
        self._cache.clear()

