"""
Secure API Key Storage System
Implements encryption, secure storage, and access control for API keys
"""

import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64


class SecurityException(Exception):
    """Custom exception for security-related errors"""
    pass


class APIKeyStorage:
    """Secure API Key Storage with encryption and access control"""
    
    def __init__(self, storage_path: str = "./keys", master_password: Optional[str] = None):
        self.storage_path = storage_path
        self.keys_file = os.path.join(storage_path, "encrypted_keys.json")
        self.audit_log = os.path.join(storage_path, "audit.log")
        
        # Create storage directory if it doesn't exist
        os.makedirs(storage_path, exist_ok=True)
        
        # Initialize encryption
        self._init_encryption(master_password)
        
        # Load existing keys
        self.keys_data = self._load_keys()
        
    def _init_encryption(self, master_password: Optional[str] = None):
        """Initialize encryption using master password or generated key"""
        if master_password:
            # Derive key from password using PBKDF2
            salt = b'stable_salt_for_demo'  # In production, use random salt stored separately
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
            self.cipher = Fernet(key)
        else:
            # Generate new key
            key_file = os.path.join(self.storage_path, ".master_key")
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    key = f.read()
            else:
                key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(key)
                # Set restrictive permissions
                os.chmod(key_file, 0o600)
            self.cipher = Fernet(key)
    
    def _load_keys(self) -> Dict:
        """Load encrypted keys from storage"""
        if os.path.exists(self.keys_file):
            try:
                with open(self.keys_file, 'r') as f:
                    encrypted_data = json.load(f)
                # Decrypt the data
                decrypted_data = {}
                for key, value in encrypted_data.items():
                    decrypted_data[key] = json.loads(
                        self.cipher.decrypt(value.encode()).decode()
                    )
                return decrypted_data
            except Exception as e:
                self._log_audit("ERROR", f"Failed to load keys: {str(e)}")
                raise SecurityException(f"Failed to decrypt keys: {str(e)}")
        return {}
    
    def _save_keys(self):
        """Save encrypted keys to storage"""
        encrypted_data = {}
        for key, value in self.keys_data.items():
            encrypted_data[key] = self.cipher.encrypt(
                json.dumps(value).encode()
            ).decode()
        
        with open(self.keys_file, 'w') as f:
            json.dump(encrypted_data, f, indent=2)
        
        # Set restrictive permissions
        os.chmod(self.keys_file, 0o600)
    
    def _log_audit(self, level: str, message: str, user: str = "system"):
        """Log security audit events"""
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] [{level}] [{user}] {message}\n"
        
        with open(self.audit_log, 'a') as f:
            f.write(log_entry)
    
    def add_api_key(self, service: str, api_key: str, user: str, 
                    metadata: Optional[Dict] = None) -> str:
        """Add new API key with encryption"""
        # Validate inputs
        if not service or not api_key or not user:
            raise ValueError("Service, API key, and user are required")
        
        # Generate unique ID
        key_id = hashlib.sha256(
            f"{service}_{user}_{secrets.token_hex(8)}".encode()
        ).hexdigest()[:16]
        
        # Store encrypted key data
        key_data = {
            "service": service,
            "api_key": api_key,
            "user": user,
            "created_at": datetime.now().isoformat(),
            "last_accessed": None,
            "access_count": 0,
            "metadata": metadata or {},
            "active": True
        }
        
        self.keys_data[key_id] = key_data
        self._save_keys()
        
        self._log_audit("INFO", f"Added API key for service: {service}", user)
        
        return key_id
    
    def get_api_key(self, key_id: str, user: str) -> Optional[str]:
        """Retrieve API key with access control"""
        if key_id not in self.keys_data:
            self._log_audit("WARNING", f"Attempted to access non-existent key: {key_id}", user)
            return None
        
        key_data = self.keys_data[key_id]
        
        # Check if key is active
        if not key_data.get("active", True):
            self._log_audit("WARNING", f"Attempted to access inactive key: {key_id}", user)
            return None
        
        # Update access metadata
        key_data["last_accessed"] = datetime.now().isoformat()
        key_data["access_count"] += 1
        self._save_keys()
        
        self._log_audit("INFO", f"Accessed API key: {key_id}", user)
        
        return key_data["api_key"]
    
    def revoke_key(self, key_id: str, user: str) -> bool:
        """Revoke an API key"""
        if key_id not in self.keys_data:
            return False
        
        self.keys_data[key_id]["active"] = False
        self.keys_data[key_id]["revoked_at"] = datetime.now().isoformat()
        self.keys_data[key_id]["revoked_by"] = user
        self._save_keys()
        
        self._log_audit("WARNING", f"Revoked API key: {key_id}", user)
        
        return True
    
    def list_keys(self, user: str, include_inactive: bool = False) -> List[Dict]:
        """List API keys (without exposing actual keys)"""
        keys_list = []
        
        for key_id, key_data in self.keys_data.items():
            if not include_inactive and not key_data.get("active", True):
                continue
            
            # Return metadata without actual API key
            safe_data = {
                "key_id": key_id,
                "service": key_data["service"],
                "user": key_data["user"],
                "created_at": key_data["created_at"],
                "last_accessed": key_data.get("last_accessed"),
                "access_count": key_data.get("access_count", 0),
                "active": key_data.get("active", True),
                "metadata": key_data.get("metadata", {})
            }
            keys_list.append(safe_data)
        
        self._log_audit("INFO", f"Listed {len(keys_list)} keys", user)
        
        return keys_list
    
    def rotate_key(self, key_id: str, new_api_key: str, user: str) -> bool:
        """Rotate an existing API key"""
        if key_id not in self.keys_data:
            return False
        
        old_key_data = self.keys_data[key_id].copy()
        
        # Create new key entry
        new_key_id = self.add_api_key(
            service=old_key_data["service"],
            api_key=new_api_key,
            user=user,
            metadata={
                **old_key_data.get("metadata", {}),
                "rotated_from": key_id,
                "rotation_date": datetime.now().isoformat()
            }
        )
        
        # Revoke old key
        self.revoke_key(key_id, user)
        
        self._log_audit("INFO", f"Rotated key {key_id} to {new_key_id}", user)
        
        return True
    
    def export_audit_log(self) -> str:
        """Export audit log for security review"""
        if os.path.exists(self.audit_log):
            with open(self.audit_log, 'r') as f:
                return f.read()
        return ""
    
    def check_key_expiry(self, days: int = 90) -> List[Dict]:
        """Check for keys that should be rotated based on age"""
        expiry_date = datetime.now() - timedelta(days=days)
        expired_keys = []
        
        for key_id, key_data in self.keys_data.items():
            if not key_data.get("active", True):
                continue
            
            created_at = datetime.fromisoformat(key_data["created_at"])
            if created_at < expiry_date:
                expired_keys.append({
                    "key_id": key_id,
                    "service": key_data["service"],
                    "created_at": key_data["created_at"],
                    "days_old": (datetime.now() - created_at).days
                })
        
        return expired_keys