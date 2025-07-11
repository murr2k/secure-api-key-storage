"""
Base Integration Module for API Key Storage
Provides common functionality for all service integrations
"""

import os
import json
import hashlib
from abc import ABC, abstractmethod
from typing import Dict, Optional, Any
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BaseIntegration(ABC):
    """Base class for all API integrations"""
    
    def __init__(self, service_name: str, config_path: Optional[str] = None):
        self.service_name = service_name
        self.config_path = config_path or self._get_default_config_path()
        self._config = self._load_config()
        self._api_key = None
        
    def _get_default_config_path(self) -> str:
        """Get default configuration path"""
        home = Path.home()
        config_dir = home / '.api_key_storage' / 'configs'
        config_dir.mkdir(parents=True, exist_ok=True)
        return str(config_dir / f'{self.service_name.lower()}_config.json')
    
    def _load_config(self) -> Dict[str, Any]:
        """Load service configuration"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading config for {self.service_name}: {e}")
                return {}
        return {}
    
    def save_config(self, config: Dict[str, Any]) -> None:
        """Save service configuration"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info(f"Configuration saved for {self.service_name}")
        except Exception as e:
            logger.error(f"Error saving config for {self.service_name}: {e}")
            raise
    
    def get_key_identifier(self) -> str:
        """Generate a unique identifier for the API key"""
        return hashlib.sha256(
            f"{self.service_name}_{self._config.get('account_id', 'default')}".encode()
        ).hexdigest()[:16]
    
    @abstractmethod
    def validate_api_key(self, api_key: str) -> bool:
        """Validate the API key format for the specific service"""
        pass
    
    @abstractmethod
    def test_connection(self, api_key: str) -> bool:
        """Test the API connection with the provided key"""
        pass
    
    def get_secure_key(self) -> Optional[str]:
        """Retrieve API key from secure storage"""
        # This is a placeholder - in production, this would integrate
        # with the secure storage backend (keychain, vault, etc.)
        if self._api_key:
            return self._api_key
        
        # Try environment variable first
        env_var = f"{self.service_name.upper()}_API_KEY"
        if env_var in os.environ:
            return os.environ[env_var]
        
        # Try config file (not recommended for production)
        if 'api_key' in self._config:
            logger.warning(f"API key found in config file for {self.service_name}. "
                         "Consider using secure storage instead.")
            return self._config['api_key']
        
        return None
    
    def set_secure_key(self, api_key: str) -> bool:
        """Store API key in secure storage"""
        # Validate key format first
        if not self.validate_api_key(api_key):
            logger.error(f"Invalid API key format for {self.service_name}")
            return False
        
        # Test connection
        if not self.test_connection(api_key):
            logger.error(f"API key validation failed for {self.service_name}")
            return False
        
        # Store in memory (in production, use secure storage)
        self._api_key = api_key
        logger.info(f"API key stored successfully for {self.service_name}")
        return True
    
    def delete_secure_key(self) -> bool:
        """Delete API key from secure storage"""
        self._api_key = None
        # Remove from config if present
        if 'api_key' in self._config:
            del self._config['api_key']
            self.save_config(self._config)
        logger.info(f"API key deleted for {self.service_name}")
        return True
    
    def get_headers(self, api_key: Optional[str] = None) -> Dict[str, str]:
        """Get authentication headers for API requests"""
        key = api_key or self.get_secure_key()
        if not key:
            raise ValueError(f"No API key available for {self.service_name}")
        return self._build_auth_headers(key)
    
    @abstractmethod
    def _build_auth_headers(self, api_key: str) -> Dict[str, str]:
        """Build authentication headers specific to the service"""
        pass
    
    def get_service_info(self) -> Dict[str, Any]:
        """Get service integration information"""
        return {
            'service_name': self.service_name,
            'config_path': self.config_path,
            'has_api_key': bool(self.get_secure_key()),
            'config': {k: v for k, v in self._config.items() if k != 'api_key'}
        }


class SecureKeyWrapper:
    """Wrapper for secure key operations across all services"""
    
    def __init__(self):
        self._integrations: Dict[str, BaseIntegration] = {}
    
    def register_integration(self, integration: BaseIntegration) -> None:
        """Register a service integration"""
        self._integrations[integration.service_name.lower()] = integration
        logger.info(f"Registered integration for {integration.service_name}")
    
    def get_key(self, service_name: str) -> Optional[str]:
        """Get API key for a specific service"""
        service = service_name.lower()
        if service not in self._integrations:
            logger.error(f"No integration registered for {service_name}")
            return None
        return self._integrations[service].get_secure_key()
    
    def set_key(self, service_name: str, api_key: str) -> bool:
        """Set API key for a specific service"""
        service = service_name.lower()
        if service not in self._integrations:
            logger.error(f"No integration registered for {service_name}")
            return False
        return self._integrations[service].set_secure_key(api_key)
    
    def delete_key(self, service_name: str) -> bool:
        """Delete API key for a specific service"""
        service = service_name.lower()
        if service not in self._integrations:
            logger.error(f"No integration registered for {service_name}")
            return False
        return self._integrations[service].delete_secure_key()
    
    def list_services(self) -> Dict[str, Dict[str, Any]]:
        """List all registered services and their info"""
        return {
            name: integration.get_service_info()
            for name, integration in self._integrations.items()
        }