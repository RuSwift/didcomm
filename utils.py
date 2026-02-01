"""
Утилиты для работы с DIDComm
"""

import json
import base64
from typing import Dict, Any, Optional


def encode_base64url(data: bytes) -> str:
    """Кодирует данные в base64url"""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def decode_base64url(data: str) -> bytes:
    """Декодирует данные из base64url"""
    # Добавляем padding если нужно
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def validate_did(did: str) -> bool:
    """
    Проверяет валидность DID строки
    
    Args:
        did: DID строка
        
    Returns:
        True если валидна, False иначе
    """
    if not did.startswith("did:"):
        return False
    
    parts = did.split(":")
    if len(parts) < 3:
        return False
    
    method = parts[1]
    method_specific_id = ":".join(parts[2:])
    
    if not method or not method_specific_id:
        return False
    
    return True


def extract_did_from_uri(uri: str) -> Optional[str]:
    """
    Извлекает DID из URI
    
    Args:
        uri: URI строка (может содержать фрагмент или путь)
        
    Returns:
        DID строка или None
    """
    if "#" in uri:
        return uri.split("#")[0]
    if "/" in uri:
        parts = uri.split("/")
        for part in parts:
            if part.startswith("did:"):
                return part
    if uri.startswith("did:"):
        return uri
    return None


def create_service_endpoint(
    endpoint: str,
    routing_keys: Optional[list] = None,
    accept: Optional[list] = None
) -> Dict[str, Any]:
    """
    Создает сервисный эндпоинт для DID документа
    
    Args:
        endpoint: URL эндпоинта
        routing_keys: Список ключей маршрутизации (опционально)
        accept: Список принимаемых типов контента (опционально)
        
    Returns:
        Словарь с описанием сервиса
    """
    service = {
        "id": "#didcomm",
        "type": "DIDCommMessaging",
        "serviceEndpoint": endpoint
    }
    
    if routing_keys:
        service["routingKeys"] = routing_keys
    
    if accept:
        service["accept"] = accept
    
    return service

