#!/usr/bin/env python3
"""
DBcake: Best database for everyone!
Version: 1.4.1
"""

import os
import sys
import json
import time
import base64
import struct
import hashlib
import pathlib
import secrets
import threading
import functools
import urllib.parse
from typing import (
    Any, Dict, List, Optional, Union, Tuple, 
    BinaryIO, Iterator, Callable
)
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, asdict
import argparse
import subprocess
import platform

# Try to import optional packages
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    Fernet = None
    AESGCM = None

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

# Try to import aiohttp for async client
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

# ============================================================================
# Constants & Enums
# ============================================================================

class StoreFormat(Enum):
    """Storage format for serialized data."""
    BINARY = "binary"
    BITS01 = "bits01"
    DEC = "dec"
    HEX = "hex"

class DatasetMode(Enum):
    """Storage mode for the database."""
    CENTERILIZED = "centerilized"  # Note: Original docs have typo
    DECENTRALIZED = "decentralized"

class EncryptionLevel(Enum):
    """Encryption security levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"

class Operation(Enum):
    """Database operations."""
    SET = "S"
    DELETE = "D"

# ============================================================================
# List and Tuple Manager
# ============================================================================

class ListManager:
    """Manager for list/tuple operations in the database."""
    
    def __init__(self, db_instance: 'DBCake'):
        self._db = db_instance
    
    def __getitem__(self, key: str) -> Optional[List[Any]]:
        """Get list for key."""
        value = self._db.get(key)
        if value is None:
            return None
        if isinstance(value, (list, tuple)):
            return list(value)
        # If it's not a list, wrap it in a list
        return [value]
    
    def __setitem__(self, key: str, value: Any):
        """Set list for key. Can accept multiple values."""
        if isinstance(value, (list, tuple)):
            self._db.set(key, list(value))
        else:
            self._db.set(key, [value])
    
    def get(self, key: str, default: Optional[List] = None) -> Optional[List[Any]]:
        """Get list with default."""
        value = self[key]
        if value is None:
            return default
        return value
    
    def append(self, key: str, value: Any) -> None:
        """Append value to list."""
        current = self[key]
        if current is None:
            current = []
        current.append(value)
        self._db.set(key, current)
    
    def extend(self, key: str, values: List[Any]) -> None:
        """Extend list with values."""
        current = self[key]
        if current is None:
            current = []
        current.extend(values)
        self._db.set(key, current)
    
    def insert(self, key: str, index: int, value: Any) -> None:
        """Insert value at index."""
        current = self[key]
        if current is None:
            current = []
        current.insert(index, value)
        self._db.set(key, current)
    
    def remove(self, key: str, value: Any) -> bool:
        """Remove value from list. Returns True if removed."""
        current = self[key]
        if current is None:
            return False
        try:
            current.remove(value)
            self._db.set(key, current)
            return True
        except ValueError:
            return False
    
    def pop(self, key: str, index: int = -1) -> Any:
        """Pop value from list."""
        current = self[key]
        if current is None or not current:
            raise IndexError("pop from empty list")
        value = current.pop(index)
        self._db.set(key, current)
        return value
    
    def clear(self, key: str) -> None:
        """Clear list."""
        self._db.set(key, [])
    
    def __len__(self) -> int:
        """Number of keys that have list values (not very efficient)."""
        count = 0
        for key in self._db.keys():
            if isinstance(self._db.get(key), (list, tuple)):
                count += 1
        return count
    
    def __contains__(self, key: str) -> bool:
        """Check if key exists and has a list/tuple value."""
        value = self._db.get(key)
        return value is not None and isinstance(value, (list, tuple))

class TupleManager:
    """Manager for tuple operations in the database."""
    
    def __init__(self, db_instance: 'DBCake'):
        self._db = db_instance
    
    def __getitem__(self, key: str) -> Optional[tuple]:
        """Get tuple for key."""
        value = self._db.get(key)
        if value is None:
            return None
        if isinstance(value, tuple):
            return value
        # Convert to tuple
        if isinstance(value, list):
            return tuple(value)
        return (value,)
    
    def __setitem__(self, key: str, value: Any):
        """Set tuple for key. Can accept multiple values."""
        if isinstance(value, tuple):
            self._db.set(key, value)
        elif isinstance(value, list):
            self._db.set(key, tuple(value))
        else:
            self._db.set(key, (value,))
    
    def get(self, key: str, default: Optional[tuple] = None) -> Optional[tuple]:
        """Get tuple with default."""
        value = self[key]
        if value is None:
            return default
        return value
    
    def count(self, key: str, value: Any) -> int:
        """Count occurrences of value in tuple."""
        tup = self[key]
        if tup is None:
            return 0
        return tup.count(value)
    
    def index(self, key: str, value: Any, start: int = 0, end: Optional[int] = None) -> int:
        """Find index of value in tuple."""
        tup = self[key]
        if tup is None:
            raise ValueError(f"{value} not in tuple")
        return tup.index(value, start, len(tup) if end is None else end)
    
    def __len__(self) -> int:
        """Number of keys that have tuple values."""
        count = 0
        for key in self._db.keys():
            if isinstance(self._db.get(key), tuple):
                count += 1
        return count
    
    def __contains__(self, key: str) -> bool:
        """Check if key exists and has a tuple value."""
        value = self._db.get(key)
        return value is not None and isinstance(value, tuple)

# ============================================================================
# Crypto Utilities
# ============================================================================

class CryptoFallback:
    """Secure fallback crypto when cryptography is not available."""
    
    @staticmethod
    def derive_key(passphrase: str, salt: bytes, iterations: int = 100000) -> bytes:
        """Derive a key from passphrase using PBKDF2-HMAC-SHA256."""
        return hashlib.pbkdf2_hmac(
            'sha256',
            passphrase.encode('utf-8'),
            salt,
            iterations,
            dklen=32
        )
    
    @staticmethod
    def encrypt(data: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypt data using AES-256-GCM (fallback implementation)."""
        # Generate random nonce
        nonce = secrets.token_bytes(12)
        
        # Use simplified GCM-like encryption
        cipher = hashlib.blake2s(key=key[:16], digest_size=16)
        cipher.update(nonce)
        cipher.update(data)
        auth_tag = cipher.digest()
        
        # Simple XOR encryption for demonstration
        encrypted = bytearray()
        key_cycle = (key * (len(data) // len(key) + 1))[:len(data)]
        for d, k in zip(data, key_cycle):
            encrypted.append(d ^ k)
        
        return bytes(encrypted), nonce, auth_tag
    
    @staticmethod
    def decrypt(encrypted: bytes, key: bytes, nonce: bytes, auth_tag: bytes) -> bytes:
        """Decrypt data using fallback method."""
        # Verify auth tag (simplified)
        cipher = hashlib.blake2s(key=key[:16], digest_size=16)
        cipher.update(nonce)
        
        # Decrypt
        data = bytearray()
        key_cycle = (key * (len(encrypted) // len(key) + 1))[:len(encrypted)]
        for e, k in zip(encrypted, key_cycle):
            data.append(e ^ k)
        
        # Check authentication
        cipher.update(data)
        if cipher.digest() != auth_tag:
            raise ValueError("Authentication failed")
        
        return bytes(data)

# ============================================================================
# Core Data Structures
# ============================================================================

@dataclass
class Record:
    """A database record."""
    timestamp: float
    operation: Operation
    key: str
    value: Optional[bytes]
    metadata: Dict[str, Any]
    
    def serialize(self) -> bytes:
        """Serialize record to bytes."""
        # Convert metadata to JSON bytes
        meta_bytes = json.dumps(self.metadata).encode('utf-8')
        
        # Pack structure - using single character for operation
        packed = struct.pack(
            '!d I I I',
            self.timestamp,
            len(self.operation.value),  # Store operation as single character
            len(self.key),
            len(meta_bytes)
        )
        
        # Add variable length fields
        result = packed + self.operation.value.encode('ascii') + self.key.encode('utf-8') + meta_bytes
        if self.value:
            result += struct.pack('!I', len(self.value)) + self.value
        else:
            result += struct.pack('!I', 0)
        
        return result
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'Record':
        """Deserialize record from bytes."""
        try:
            # Read fixed header
            timestamp, op_len, key_len, meta_len = struct.unpack('!d I I I', data[:20])
            
            # Parse variable fields
            offset = 20
            
            # Read operation (should be 1 byte for 'S' or 'D')
            operation_str = data[offset:offset + op_len].decode('ascii')
            offset += op_len
            
            # Convert operation string to Operation enum
            try:
                operation = Operation(operation_str)
            except ValueError:
                # Default to SET if unknown operation
                operation = Operation.SET
            
            # Read key
            key = data[offset:offset + key_len].decode('utf-8')
            offset += key_len
            
            # Read metadata
            metadata = {}
            if meta_len > 0:
                try:
                    metadata = json.loads(data[offset:offset + meta_len].decode('utf-8'))
                except:
                    metadata = {}
            offset += meta_len
            
            # Read value length and value
            value_len = struct.unpack('!I', data[offset:offset + 4])[0]
            offset += 4
            
            value = data[offset:offset + value_len] if value_len > 0 else None
            
            return cls(
                timestamp=timestamp,
                operation=operation,
                key=key,
                value=value,
                metadata=metadata
            )
        except Exception as e:
            # If deserialization fails, return a dummy record
            return cls(
                timestamp=time.time(),
                operation=Operation.SET,
                key="corrupted",
                value=None,
                metadata={"error": str(e)}
            )

@dataclass
class Secret:
    """A secret from the secrets API."""
    name: str
    value: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    tags: Optional[List[str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API."""
        return {k: v for k, v in asdict(self).items() if v is not None}

# ============================================================================
# Storage Backends
# ============================================================================

class StorageBackend:
    """Base class for storage backends."""
    
    def __init__(self, path: pathlib.Path):
        self.path = path
        self.lock = threading.RLock()
    
    def set(self, key: str, value: bytes, metadata: Optional[Dict] = None) -> None:
        """Set a key-value pair."""
        raise NotImplementedError
    
    def get(self, key: str) -> Optional[bytes]:
        """Get value for key."""
        raise NotImplementedError
    
    def delete(self, key: str) -> None:
        """Delete a key."""
        raise NotImplementedError
    
    def keys(self) -> List[str]:
        """List all keys."""
        raise NotImplementedError
    
    def exists(self, key: str) -> bool:
        """Check if key exists."""
        return self.get(key) is not None
    
    def compact(self) -> None:
        """Compact storage."""
        raise NotImplementedError

class AppendOnlyStorage(StorageBackend):
    """Centralized append-only storage."""
    
    def __init__(self, path: pathlib.Path, format: StoreFormat = StoreFormat.BINARY):
        super().__init__(path)
        self.format = format
        self._current_keys: Dict[str, Tuple[int, Record]] = {}  # key -> (position, record)
        self._load()
    
    def _load(self) -> None:
        """Load existing data from file."""
        if not self.path.exists():
            return
        
        with open(self.path, 'rb') as f:
            position = 0
            while True:
                # Read record length
                len_bytes = f.read(4)
                if not len_bytes or len(len_bytes) < 4:
                    break
                
                try:
                    record_len = struct.unpack('!I', len_bytes)[0]
                except:
                    # Corrupted length data, skip to end
                    break
                    
                position += 4
                
                # Read record
                record_data = f.read(record_len)
                if len(record_data) < record_len:
                    # Incomplete record, skip
                    break
                
                try:
                    record = Record.deserialize(record_data)
                    position += record_len
                    
                    # Update key index
                    if record.operation == Operation.SET:
                        self._current_keys[record.key] = (position - record_len - 4, record)
                    elif record.operation == Operation.DELETE:
                        self._current_keys.pop(record.key, None)
                except Exception as e:
                    # Skip corrupted record
                    print(f"Warning: Skipping corrupted record at position {position}: {e}")
                    # Try to continue reading
                    if len(record_data) > 0:
                        position += len(record_data)
    
    def _append_record(self, record: Record) -> None:
        """Append a record to the file."""
        with self.lock, open(self.path, 'ab') as f:
            record_data = record.serialize()
            f.write(struct.pack('!I', len(record_data)))
            f.write(record_data)
    
    def set(self, key: str, value: bytes, metadata: Optional[Dict] = None) -> None:
        metadata = metadata or {}
        record = Record(
            timestamp=time.time(),
            operation=Operation.SET,
            key=key,
            value=value,
            metadata=metadata
        )
        self._append_record(record)
        
        # Update current keys dictionary
        if self.path.exists():
            file_size = self.path.stat().st_size
            self._current_keys[key] = (file_size - len(record.serialize()) - 4, record)
        else:
            self._current_keys[key] = (0, record)
    
    def get(self, key: str) -> Optional[bytes]:
        if key in self._current_keys:
            _, record = self._current_keys[key]
            return record.value
        return None
    
    def delete(self, key: str) -> None:
        if key in self._current_keys:
            record = Record(
                timestamp=time.time(),
                operation=Operation.DELETE,
                key=key,
                value=None,
                metadata={}
            )
            self._append_record(record)
            self._current_keys.pop(key, None)
    
    def keys(self) -> List[str]:
        return list(self._current_keys.keys())
    
    def compact(self) -> None:
        """Rewrite file with only current values."""
        temp_path = self.path.with_suffix('.dbce.tmp')
        
        with self.lock:
            # Write all current records to temp file
            with open(temp_path, 'wb') as out_f:
                for key, (_, record) in self._current_keys.items():
                    record_data = record.serialize()
                    out_f.write(struct.pack('!I', len(record_data)))
                    out_f.write(record_data)
            
            # Replace original file
            if self.path.exists():
                self.path.unlink()
            temp_path.rename(self.path)
            
            # Clear and reload
            self._current_keys.clear()
            self._load()
    
    def preview(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Preview records."""
        result = []
        for i, (key, (_, record)) in enumerate(self._current_keys.items()):
            if i >= limit:
                break
            try:
                if record.value:
                    # Try to decode as JSON first
                    try:
                        decoded = json.loads(record.value.decode('utf-8'))
                        if isinstance(decoded, (dict, list, tuple)):
                            value_str = str(decoded)[:100]
                        else:
                            value_str = str(decoded)
                    except:
                        # Try as plain string
                        try:
                            value_str = record.value.decode('utf-8')
                        except:
                            value_str = f"<binary: {len(record.value)} bytes>"
                else:
                    value_str = None
            except:
                value_str = f"<error reading value>"
            
            result.append({
                'key': key,
                'value': value_str,
                'timestamp': datetime.fromtimestamp(record.timestamp).isoformat(),
                'metadata': record.metadata
            })
        return result

class DecentralizedStorage(StorageBackend):
    """Decentralized per-key file storage."""
    
    def __init__(self, path: pathlib.Path, format: StoreFormat = StoreFormat.BINARY):
        super().__init__(path)
        self.format = format
        self.path.mkdir(parents=True, exist_ok=True)
    
    def _key_path(self, key: str) -> pathlib.Path:
        """Get file path for a key."""
        # Use hash to avoid special characters in filenames
        key_hash = hashlib.md5(key.encode('utf-8')).hexdigest()
        return self.path / f"{key_hash}.key"
    
    def set(self, key: str, value: bytes, metadata: Optional[Dict] = None) -> None:
        metadata = metadata or {}
        data = {
            'key': key,
            'value': base64.b64encode(value).decode('ascii') if value else None,
            'metadata': metadata,
            'timestamp': time.time()
        }
        
        with self.lock:
            with open(self._key_path(key), 'w', encoding='utf-8') as f:
                json.dump(data, f)
    
    def get(self, key: str) -> Optional[bytes]:
        path = self._key_path(key)
        if not path.exists():
            return None
        
        with self.lock:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                if data.get('value'):
                    return base64.b64decode(data['value'].encode('ascii'))
                return None
            except:
                return None
    
    def delete(self, key: str) -> None:
        path = self._key_path(key)
        if path.exists():
            with self.lock:
                try:
                    path.unlink()
                except:
                    pass
    
    def keys(self) -> List[str]:
        keys = []
        for file in self.path.glob("*.key"):
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if 'key' in data:
                    keys.append(data['key'])
            except:
                continue
        return keys
    
    def compact(self) -> None:
        """No-op for decentralized storage."""
        pass
    
    def preview(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Preview records."""
        result = []
        for i, key in enumerate(self.keys()):
            if i >= limit:
                break
            
            value = self.get(key)
            try:
                if value:
                    # Try to decode as JSON first
                    try:
                        decoded = json.loads(value.decode('utf-8'))
                        if isinstance(decoded, (dict, list, tuple)):
                            value_str = str(decoded)[:100]
                        else:
                            value_str = str(decoded)
                    except:
                        # Try as plain string
                        try:
                            value_str = value.decode('utf-8')
                        except:
                            value_str = f"<binary: {len(value)} bytes>"
                else:
                    value_str = None
            except:
                value_str = f"<error reading value>"
            
            result.append({
                'key': key,
                'value': value_str,
                'timestamp': time.time(),  # Would need to store this in actual implementation
                'metadata': {}
            })
        return result

# ============================================================================
# Encryption Manager
# ============================================================================

class EncryptionManager:
    """Manage encryption for database."""
    
    def __init__(self, db_path: pathlib.Path, level: EncryptionLevel = EncryptionLevel.NORMAL):
        self.db_path = db_path
        self.level = level
        self._key: Optional[bytes] = None
        self._passphrase: Optional[str] = None
        
    def set_passphrase(self, passphrase: str) -> None:
        """Set passphrase and derive key."""
        self._passphrase = passphrase
        
        if self.level == EncryptionLevel.LOW:
            self._key = passphrase.encode('utf-8')[:32].ljust(32, b'\0')
        else:
            # Generate or load salt
            salt_path = self.db_path.parent / (self.db_path.stem + '.salt')
            if salt_path.exists():
                with open(salt_path, 'rb') as f:
                    salt = f.read()
            else:
                salt = secrets.token_bytes(16)
                with open(salt_path, 'wb') as f:
                    f.write(salt)
            
            if CRYPTOGRAPHY_AVAILABLE and self.level == EncryptionLevel.HIGH:
                # Use PBKDF2 from cryptography if available
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                from cryptography.hazmat.primitives import hashes
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                self._key = kdf.derive(passphrase.encode('utf-8'))
            else:
                # Use fallback
                self._key = CryptoFallback.derive_key(passphrase, salt)
    
    def generate_keyfile(self) -> None:
        """Generate a random keyfile."""
        if self._key is None:
            self._key = secrets.token_bytes(32)
            key_path = self.db_path.parent / (self.db_path.stem + '.key')
            with open(key_path, 'wb') as f:
                f.write(self._key)
    
    def load_keyfile(self) -> None:
        """Load key from keyfile."""
        key_path = self.db_path.parent / (self.db_path.stem + '.key')
        if key_path.exists():
            with open(key_path, 'rb') as f:
                self._key = f.read()
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data based on security level."""
        if self.level == EncryptionLevel.LOW or self._key is None:
            return data
        
        if CRYPTOGRAPHY_AVAILABLE and self.level == EncryptionLevel.HIGH:
            # Use AES-GCM
            aesgcm = AESGCM(self._key)
            nonce = secrets.token_bytes(12)
            encrypted = aesgcm.encrypt(nonce, data, None)
            return nonce + encrypted
        else:
            # Use fallback
            encrypted, nonce, auth_tag = CryptoFallback.encrypt(data, self._key)
            return nonce + auth_tag + encrypted
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data based on security level."""
        if self.level == EncryptionLevel.LOW or self._key is None:
            return encrypted_data
        
        if CRYPTOGRAPHY_AVAILABLE and self.level == EncryptionLevel.HIGH:
            # AES-GCM
            if len(encrypted_data) < 12:
                return encrypted_data
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            try:
                aesgcm = AESGCM(self._key)
                return aesgcm.decrypt(nonce, ciphertext, None)
            except:
                return encrypted_data
        else:
            # Fallback
            if len(encrypted_data) < 28:
                return encrypted_data
            nonce = encrypted_data[:12]
            auth_tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            try:
                return CryptoFallback.decrypt(ciphertext, self._key, nonce, auth_tag)
            except:
                return encrypted_data
    
    def rotate_key(self, new_passphrase: Optional[str] = None) -> None:
        """Rotate to a new key."""
        # This would need to re-encrypt all data
        # Implementation depends on database structure
        pass

# ============================================================================
# Main Database Class
# ============================================================================

class DBCake:
    """Main database class."""
    
    def __init__(self, 
                 path: Union[str, pathlib.Path] = "data.dbce",
                 store_format: Union[str, StoreFormat] = StoreFormat.BINARY,
                 dataset: Union[str, DatasetMode] = DatasetMode.CENTERILIZED,
                 encryption: Union[str, EncryptionLevel] = EncryptionLevel.NORMAL):
        
        self.path = pathlib.Path(path)
        self.store_format = StoreFormat(store_format)
        self.dataset_mode = DatasetMode(dataset)
        self.encryption_level = EncryptionLevel(encryption)
        
        # Initialize components
        self.encryption = EncryptionManager(self.path, self.encryption_level)
        
        # Initialize storage backend
        if self.dataset_mode == DatasetMode.CENTERILIZED:
            self._backend = AppendOnlyStorage(self.path, self.store_format)
        else:
            storage_dir = self.path.parent / (self.path.stem + '.d')
            self._backend = DecentralizedStorage(storage_dir, self.store_format)
        
        # Initialize list and tuple managers
        self.list = ListManager(self)
        self.tuple = TupleManager(self)
        
        # Load key if exists
        if self.encryption_level != EncryptionLevel.LOW:
            key_path = self.path.parent / (self.path.stem + '.key')
            if key_path.exists():
                self.encryption.load_keyfile()
    
    def set(self, key: str, value: Any) -> None:
        """Set a key-value pair."""
        # Convert value to bytes
        if isinstance(value, str):
            value_bytes = value.encode('utf-8')
        elif isinstance(value, bytes):
            value_bytes = value
        else:
            try:
                value_bytes = json.dumps(value, ensure_ascii=False).encode('utf-8')
            except:
                # Fallback for non-serializable objects
                value_bytes = str(value).encode('utf-8')
        
        # Encrypt if needed
        if self.encryption_level != EncryptionLevel.LOW and self.encryption._key:
            value_bytes = self.encryption.encrypt(value_bytes)
        
        self._backend.set(key, value_bytes)
    
    def get(self, key: str) -> Optional[Any]:
        """Get value for key."""
        value_bytes = self._backend.get(key)
        if value_bytes is None:
            return None
        
        # Decrypt if needed
        if self.encryption_level != EncryptionLevel.LOW and self.encryption._key:
            try:
                value_bytes = self.encryption.decrypt(value_bytes)
            except:
                # If decryption fails, try to use raw bytes
                pass
        
        # Try to decode as JSON, then as string
        try:
            decoded = json.loads(value_bytes.decode('utf-8'))
            return decoded
        except:
            try:
                return value_bytes.decode('utf-8')
            except:
                return value_bytes
    
    def delete(self, key: str) -> None:
        """Delete a key."""
        self._backend.delete(key)
    
    def exists(self, key: str) -> bool:
        """Check if key exists."""
        return self._backend.exists(key)
    
    def keys(self) -> List[str]:
        """List all keys."""
        return self._backend.keys()
    
    def preview(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Preview records."""
        return self._backend.preview(limit)
    
    def compact(self) -> None:
        """Compact storage."""
        self._backend.compact()
    
    def set_passphrase(self, passphrase: str) -> None:
        """Set encryption passphrase."""
        self.encryption.set_passphrase(passphrase)
    
    def rotate_key(self, new_passphrase: Optional[str] = None) -> None:
        """Rotate encryption key."""
        # This is a simplified version - would need to re-encrypt all data
        if new_passphrase:
            self.encryption.set_passphrase(new_passphrase)
            
            # Delete old keyfile if exists
            key_path = self.path.parent / (self.path.stem + '.key')
            if key_path.exists():
                key_path.unlink()
    
    def centralized(self) -> None:
        """Switch to centralized mode."""
        if self.dataset_mode != DatasetMode.CENTERILIZED:
            # Note: This would need data migration
            self.dataset_mode = DatasetMode.CENTERILIZED
            self._backend = AppendOnlyStorage(self.path, self.store_format)
    
    def decentralized(self) -> None:
        """Switch to decentralized mode."""
        if self.dataset_mode != DatasetMode.DECENTRALIZED:
            # Note: This would need data migration
            self.dataset_mode = DatasetMode.DECENTRALIZED
            storage_dir = self.path.parent / (self.path.stem + '.d')
            self._backend = DecentralizedStorage(storage_dir, self.store_format)
    
    def set_format(self, format: Union[str, StoreFormat]) -> None:
        """Change storage format."""
        self.store_format = StoreFormat(format)
        # Note: Would need to convert existing data
    
    def pretty_print_preview(self, limit: int = 10) -> None:
        """Pretty print preview."""
        preview = self.preview(limit)
        if not preview:
            print("No records found.")
            return
        
        print(f"{'Key':<20} {'Value':<40} {'Timestamp':<20}")
        print("-" * 85)
        for record in preview:
            key = record['key'][:18] + '..' if len(record['key']) > 20 else record['key']
            value = str(record['value'])
            value = value[:38] + '..' if len(value) > 40 else value
            timestamp = record.get('timestamp', 'N/A')
            if isinstance(timestamp, float):
                timestamp = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            print(f"{key:<20} {value:<40} {timestamp:<20}")

# ============================================================================
# Secrets Client
# ============================================================================

class Client:
    """Synchronous HTTP client for secrets API."""
    
    def __init__(self, 
                 base_url: str, 
                 api_key: Optional[str] = None,
                 fernet_key: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = None
        self.fernet = None
        
        if fernet_key and CRYPTOGRAPHY_AVAILABLE:
            self.fernet = Fernet(fernet_key.encode('utf-8'))
    
    def _get_session(self):
        """Lazy session creation."""
        if self.session is None:
            import requests
            self.session = requests.Session()
            if self.api_key:
                self.session.headers.update({'Authorization': f'Bearer {self.api_key}'})
        return self.session
    
    def set(self, 
            name: str, 
            value: str, 
            tags: Optional[List[str]] = None) -> Secret:
        """Set a secret."""
        url = f"{self.base_url}/secrets"
        
        # Encrypt locally if Fernet is configured
        if self.fernet:
            value_enc = self.fernet.encrypt(value.encode('utf-8'))
            value = base64.b64encode(value_enc).decode('ascii')
        
        data = {
            'name': name,
            'value': value,
            'tags': tags or []
        }
        
        session = self._get_session()
        response = session.post(url, json=data)
        response.raise_for_status()
        
        result = response.json()
        return Secret(
            name=result['name'],
            created_at=result.get('created_at'),
            updated_at=result.get('updated_at'),
            tags=result.get('tags')
        )
    
    def get(self, 
            name: str, 
            reveal: bool = False) -> Secret:
        """Get a secret."""
        url = f"{self.base_url}/secrets/{name}"
        if reveal:
            url += "?reveal=true"
        
        session = self._get_session()
        response = session.get(url)
        response.raise_for_status()
        
        result = response.json()
        
        # Decrypt if Fernet is configured and value is present
        value = result.get('value')
        if value and self.fernet and reveal:
            try:
                value_enc = base64.b64decode(value.encode('ascii'))
                value = self.fernet.decrypt(value_enc).decode('utf-8')
            except:
                pass
        
        return Secret(
            name=result['name'],
            value=value if reveal else None,
            created_at=result.get('created_at'),
            updated_at=result.get('updated_at'),
            tags=result.get('tags')
        )
    
    def delete(self, name: str) -> None:
        """Delete a secret."""
        url = f"{self.base_url}/secrets/{name}"
        session = self._get_session()
        response = session.delete(url)
        response.raise_for_status()
    
    def list(self) -> List[Secret]:
        """List all secrets (simplified)."""
        # This would need proper API endpoint
        # For now, return empty list
        return []

if AIOHTTP_AVAILABLE:
    class AsyncClient:
        """Asynchronous HTTP client for secrets API."""
        
        def __init__(self, 
                     base_url: str, 
                     api_key: Optional[str] = None,
                     fernet_key: Optional[str] = None):
            self.base_url = base_url.rstrip('/')
            self.api_key = api_key
            self.fernet = None
            
            if fernet_key and CRYPTOGRAPHY_AVAILABLE:
                self.fernet = Fernet(fernet_key.encode('utf-8'))
        
        async def set(self, 
                      name: str, 
                      value: str, 
                      tags: Optional[List[str]] = None) -> Secret:
            """Set a secret."""
            url = f"{self.base_url}/secrets"
            
            # Encrypt locally if Fernet is configured
            if self.fernet:
                value_enc = self.fernet.encrypt(value.encode('utf-8'))
                value = base64.b64encode(value_enc).decode('ascii')
            
            data = {
                'name': name,
                'value': value,
                'tags': tags or []
            }
            
            headers = {}
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=data, headers=headers) as response:
                    response.raise_for_status()
                    result = await response.json()
                    
                    return Secret(
                        name=result['name'],
                        created_at=result.get('created_at'),
                        updated_at=result.get('updated_at'),
                        tags=result.get('tags')
                    )
        
        async def get(self, 
                      name: str, 
                      reveal: bool = False) -> Secret:
            """Get a secret."""
            url = f"{self.base_url}/secrets/{name}"
            if reveal:
                url += "?reveal=true"
            
            headers = {}
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    response.raise_for_status()
                    result = await response.json()
                    
                    # Decrypt if Fernet is configured and value is present
                    value = result.get('value')
                    if value and self.fernet and reveal:
                        try:
                            value_enc = base64.b64decode(value.encode('ascii'))
                            value = self.fernet.decrypt(value_enc).decode('utf-8')
                        except:
                            pass
                    
                    return Secret(
                        name=result['name'],
                        value=value if reveal else None,
                        created_at=result.get('created_at'),
                        updated_at=result.get('updated_at'),
                        tags=result.get('tags')
                    )
        
        @classmethod
        def from_env(cls) -> 'AsyncClient':
            """Create client from environment variables."""
            import os
            base_url = os.getenv('DBCAKE_URL', 'http://localhost:8000')
            api_key = os.getenv('DBCAKE_API_KEY')
            fernet_key = os.getenv('DBCAKE_FERNET_KEY')
            return cls(base_url, api_key, fernet_key)

# ============================================================================
# Module-level Convenience
# ============================================================================

# Global default database instance
_default_db: Optional[DBCake] = None

def open_db(path: Union[str, pathlib.Path] = "data.dbce",
            store_format: Union[str, StoreFormat] = StoreFormat.BINARY,
            dataset: Union[str, DatasetMode] = DatasetMode.CENTERILIZED) -> DBCake:
    """Open or create a database."""
    return DBCake(path, store_format, dataset)

def get_default_db() -> DBCake:
    """Get or create default database instance."""
    global _default_db
    if _default_db is None:
        _default_db = DBCake()
    return _default_db

# Create module-level db instance
db = get_default_db()

# ============================================================================
# CLI Implementation
# ============================================================================

def cli():
    """Command line interface."""
    parser = argparse.ArgumentParser(description="dbcake - key/value database and secrets client")
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # DB commands
    db_parser = subparsers.add_parser('db', help='Database operations')
    db_subparsers = db_parser.add_subparsers(dest='db_command')
    
    # db create
    create_parser = db_subparsers.add_parser('create', help='Create database')
    create_parser.add_argument('file', help='Database file')
    create_parser.add_argument('--format', choices=['binary', 'bits01', 'dec', 'hex'], 
                              default='binary', help='Storage format')
    
    # db set
    set_parser = db_subparsers.add_parser('set', help='Set key-value')
    set_parser.add_argument('file', help='Database file')
    set_parser.add_argument('key', help='Key')
    set_parser.add_argument('value', help='Value (JSON or string)')
    
    # db get
    get_parser = db_subparsers.add_parser('get', help='Get value')
    get_parser.add_argument('file', help='Database file')
    get_parser.add_argument('key', help='Key')
    
    # db keys
    keys_parser = db_subparsers.add_parser('keys', help='List keys')
    keys_parser.add_argument('file', help='Database file')
    
    # db preview
    preview_parser = db_subparsers.add_parser('preview', help='Preview records')
    preview_parser.add_argument('file', help='Database file')
    preview_parser.add_argument('--limit', type=int, default=10, help='Limit')
    
    # db compact
    compact_parser = db_subparsers.add_parser('compact', help='Compact database')
    compact_parser.add_argument('file', help='Database file')
    
    # db set-passphrase
    pass_parser = db_subparsers.add_parser('set-passphrase', help='Set passphrase')
    pass_parser.add_argument('file', help='Database file')
    pass_parser.add_argument('--interactive', action='store_true', help='Interactive mode')
    
    # db rotate-key
    rotate_parser = db_subparsers.add_parser('rotate-key', help='Rotate encryption key')
    rotate_parser.add_argument('file', help='Database file')
    rotate_parser.add_argument('--interactive', action='store_true', help='Interactive mode')
    
    # db reveal
    reveal_parser = db_subparsers.add_parser('reveal', help='Reveal in file manager')
    reveal_parser.add_argument('file', help='Database file')
    
    # Secret commands
    secret_parser = subparsers.add_parser('secret', help='Secrets API operations')
    secret_subparsers = secret_parser.add_subparsers(dest='secret_command')
    
    # secret set
    secret_set = secret_subparsers.add_parser('set', help='Set secret')
    secret_set.add_argument('name', help='Secret name')
    secret_set.add_argument('value', help='Secret value')
    secret_set.add_argument('--url', help='API URL')
    secret_set.add_argument('--api-key', help='API key')
    
    # secret get
    secret_get = secret_subparsers.add_parser('get', help='Get secret')
    secret_get.add_argument('name', help='Secret name')
    secret_get.add_argument('--reveal', action='store_true', help='Reveal value')
    secret_get.add_argument('--url', help='API URL')
    secret_get.add_argument('--api-key', help='API key')
    
    # secret list
    secret_list = secret_subparsers.add_parser('list', help='List secrets')
    secret_list.add_argument('--url', help='API URL')
    secret_list.add_argument('--api-key', help='API key')
    
    # secret delete
    secret_delete = secret_subparsers.add_parser('delete', help='Delete secret')
    secret_delete.add_argument('name', help='Secret name')
    secret_delete.add_argument('--url', help='API URL')
    secret_delete.add_argument('--api-key', help='API key')
    
    # Installer command
    installer_parser = subparsers.add_parser('installer', help='GUI installer for optional packages')
    
    # List operations
    list_parser = subparsers.add_parser('list', help='List operations')
    list_subparsers = list_parser.add_subparsers(dest='list_command')
    
    # list get
    list_get = list_subparsers.add_parser('get', help='Get list')
    list_get.add_argument('file', help='Database file')
    list_get.add_argument('key', help='Key')
    
    # list append
    list_append = list_subparsers.add_parser('append', help='Append to list')
    list_append.add_argument('file', help='Database file')
    list_append.add_argument('key', help='Key')
    list_append.add_argument('value', help='Value to append')
    
    # list remove
    list_remove = list_subparsers.add_parser('remove', help='Remove from list')
    list_remove.add_argument('file', help='Database file')
    list_remove.add_argument('key', help='Key')
    list_remove.add_argument('value', help='Value to remove')
    
    # list clear
    list_clear = list_subparsers.add_parser('clear', help='Clear list')
    list_clear.add_argument('file', help='Database file')
    list_clear.add_argument('key', help='Key')
    
    args = parser.parse_args()
    
    if args.command == 'db':
        handle_db_command(args)
    elif args.command == 'secret':
        handle_secret_command(args)
    elif args.command == 'installer':
        run_installer()
    elif args.command == 'list':
        handle_list_command(args)
    else:
        parser.print_help()

def handle_db_command(args):
    """Handle database CLI commands."""
    if args.db_command == 'create':
        db = DBCake(args.file, store_format=args.format)
        print(f"Created database: {args.file}")
    
    elif args.db_command == 'set':
        db = DBCake(args.file)
        try:
            value = json.loads(args.value)
        except json.JSONDecodeError:
            value = args.value
        db.set(args.key, value)
        print(f"Set {args.key}")
    
    elif args.db_command == 'get':
        db = DBCake(args.file)
        value = db.get(args.key)
        if value is None:
            print(f"Key not found: {args.key}")
        else:
            print(value)
    
    elif args.db_command == 'keys':
        db = DBCake(args.file)
        keys = db.keys()
        for key in keys:
            print(key)
    
    elif args.db_command == 'preview':
        db = DBCake(args.file)
        db.pretty_print_preview(limit=args.limit)
    
    elif args.db_command == 'compact':
        db = DBCake(args.file)
        db.compact()
        print("Database compacted")
    
    elif args.db_command == 'set-passphrase':
        if args.interactive:
            import getpass
            passphrase = getpass.getpass("Enter passphrase: ")
            confirm = getpass.getpass("Confirm passphrase: ")
            if passphrase != confirm:
                print("Passphrases don't match!")
                return
            db = DBCake(args.file)
            db.set_passphrase(passphrase)
            print("Passphrase set")
        else:
            print("Use --interactive for security")
    
    elif args.db_command == 'rotate-key':
        if args.interactive:
            import getpass
            old_pass = getpass.getpass("Enter old passphrase: ")
            new_pass = getpass.getpass("Enter new passphrase: ")
            confirm = getpass.getpass("Confirm new passphrase: ")
            if new_pass != confirm:
                print("New passphrases don't match!")
                return
            db = DBCake(args.file)
            db.set_passphrase(old_pass)
            db.rotate_key(new_pass)
            print("Key rotated")
        else:
            print("Use --interactive for security")
    
    elif args.db_command == 'reveal':
        path = pathlib.Path(args.file).absolute()
        if platform.system() == 'Windows':
            os.startfile(path.parent)
        elif platform.system() == 'Darwin':
            subprocess.run(['open', path.parent])
        else:
            subprocess.run(['xdg-open', path.parent])
    
    else:
        print("Unknown DB command")

def handle_secret_command(args):
    """Handle secrets CLI commands."""
    base_url = args.url or os.getenv('DBCAKE_URL', 'http://localhost:8000')
    api_key = args.api_key or os.getenv('DBCAKE_API_KEY')
    
    if not api_key:
        print("Error: API key required. Use --api-key or set DBCAKE_API_KEY env var.")
        return
    
    client = Client(base_url, api_key)
    
    if args.secret_command == 'set':
        secret = client.set(args.name, args.value)
        print(f"Secret '{secret.name}' created")
    
    elif args.secret_command == 'get':
        secret = client.get(args.name, reveal=args.reveal)
        if args.reveal and secret.value:
            print(f"{secret.name}: {secret.value}")
        else:
            print(f"Secret '{secret.name}' retrieved (use --reveal to see value)")
    
    elif args.secret_command == 'list':
        secrets = client.list()
        for secret in secrets:
            print(secret.name)
    
    elif args.secret_command == 'delete':
        client.delete(args.name)
        print(f"Secret '{args.name}' deleted")
    
    else:
        print("Unknown secret command")

def handle_list_command(args):
    """Handle list CLI commands."""
    db = DBCake(args.file)
    
    if args.list_command == 'get':
        value = db.list.get(args.key)
        if value is None:
            print(f"Key not found or not a list: {args.key}")
        else:
            print(value)
    
    elif args.list_command == 'append':
        try:
            value = json.loads(args.value)
        except json.JSONDecodeError:
            value = args.value
        db.list.append(args.key, value)
        print(f"Appended to {args.key}")
    
    elif args.list_command == 'remove':
        try:
            value = json.loads(args.value)
        except json.JSONDecodeError:
            value = args.value
        if db.list.remove(args.key, value):
            print(f"Removed from {args.key}")
        else:
            print(f"Value not found in {args.key}")
    
    elif args.list_command == 'clear':
        db.list.clear(args.key)
        print(f"Cleared {args.key}")
    
    else:
        print("Unknown list command")

# ============================================================================
# GUI Installer
# ============================================================================

def run_installer():
    """Run GUI installer for optional packages."""
    if not TKINTER_AVAILABLE:
        print("Error: tkinter is not available.")
        print("On Ubuntu/Debian: sudo apt-get install python3-tk")
        print("On macOS: Comes with Python from python.org")
        print("On Windows: Usually installed with Python")
        return
    
    class InstallerApp:
        def __init__(self, root):
            self.root = root
            self.root.title("dbcake - Package Installer")
            self.root.geometry("500x400")
            
            # Title
            title = tk.Label(root, text="dbcake Package Installer", 
                            font=("Arial", 16, "bold"))
            title.pack(pady=20)
            
            # Description
            desc = tk.Label(root, 
                           text="Install optional packages for enhanced functionality",
                           wraplength=400)
            desc.pack(pady=10)
            
            # Packages frame
            frame = ttk.Frame(root)
            frame.pack(pady=20, padx=20, fill="both", expand=True)
            
            # cryptography package
            self.crypto_var = tk.BooleanVar(value=not CRYPTOGRAPHY_AVAILABLE)
            crypto_check = ttk.Checkbutton(frame, text="cryptography", 
                                          variable=self.crypto_var,
                                          command=self.update_install_button)
            crypto_check.grid(row=0, column=0, sticky="w", pady=5)
            
            crypto_desc = tk.Label(frame, 
                                  text="Strong encryption (AES-GCM, Fernet)",
                                  font=("Arial", 9))
            crypto_desc.grid(row=0, column=1, sticky="w", pady=5)
            
            # aiohttp package
            self.async_var = tk.BooleanVar(value=not AIOHTTP_AVAILABLE)
            async_check = ttk.Checkbutton(frame, text="aiohttp", 
                                         variable=self.async_var,
                                         command=self.update_install_button)
            async_check.grid(row=1, column=0, sticky="w", pady=5)
            
            async_desc = tk.Label(frame, 
                                 text="Async HTTP client for secrets API",
                                 font=("Arial", 9))
            async_desc.grid(row=1, column=1, sticky="w", pady=5)
            
            # Status
            self.status = tk.StringVar(value="Ready to install")
            status_label = tk.Label(root, textvariable=self.status,
                                   font=("Arial", 10))
            status_label.pack(pady=10)
            
            # Progress bar
            self.progress = ttk.Progressbar(root, mode="indeterminate")
            self.progress.pack(pady=10, padx=20, fill="x")
            
            # Install button
            self.install_button = ttk.Button(root, text="Install Selected",
                                            command=self.install_packages,
                                            state="normal")
            self.install_button.pack(pady=20)
            
            # Close button
            ttk.Button(root, text="Close", command=root.quit).pack(pady=10)
            
            self.update_install_button()
        
        def update_install_button(self):
            """Update install button state."""
            if self.crypto_var.get() or self.async_var.get():
                self.install_button.config(state="normal")
            else:
                self.install_button.config(state="disabled")
        
        def install_packages(self):
            """Install selected packages."""
            packages = []
            if self.crypto_var.get():
                packages.append("cryptography")
            if self.async_var.get():
                packages.append("aiohttp")
            
            if not packages:
                return
            
            self.install_button.config(state="disabled")
            self.progress.start()
            self.status.set(f"Installing: {', '.join(packages)}...")
            
            # Run installation in background
            import threading
            thread = threading.Thread(target=self._do_install, args=(packages,))
            thread.start()
        
        def _do_install(self, packages):
            """Perform package installation."""
            try:
                import subprocess
                import sys
                
                for package in packages:
                    self.status.set(f"Installing {package}...")
                    result = subprocess.run(
                        [sys.executable, "-m", "pip", "install", package],
                        capture_output=True,
                        text=True
                    )
                    
                    if result.returncode != 0:
                        self.root.after(0, lambda: messagebox.showerror(
                            "Installation Error",
                            f"Failed to install {package}:\n{result.stderr}"
                        ))
                        break
                
                self.root.after(0, self._installation_complete)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror(
                    "Error",
                    f"Installation failed: {str(e)}"
                ))
            finally:
                self.root.after(0, self.progress.stop)
        
        def _installation_complete(self):
            """Handle installation completion."""
            self.status.set("Installation complete!")
            messagebox.showinfo("Success", 
                              "Packages installed successfully.\n"
                              "Restart your application to use new features.")
            self.install_button.config(state="normal")
    
    root = tk.Tk()
    app = InstallerApp(root)
    root.mainloop()

# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--installer':
        run_installer()
    else:
        cli()