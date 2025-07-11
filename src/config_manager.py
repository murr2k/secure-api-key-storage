"""
Configuration Management System for Multiple API Keys

This module provides a comprehensive configuration system for managing
multiple API keys across different services and environments.
"""

import os
import json
import yaml
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum

from secure_storage import SecureKeyStorage


class ServiceProvider(Enum):
    """Supported API service providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    AWS = "aws"
    AZURE = "azure"
    HUGGINGFACE = "huggingface"
    CUSTOM = "custom"


@dataclass
class APIKeyConfig:
    """Configuration for a single API key."""
    name: str
    provider: ServiceProvider
    environment: str = "production"
    endpoint: Optional[str] = None
    version: Optional[str] = None
    rate_limit: Optional[int] = None
    expiry: Optional[str] = None
    tags: List[str] = None
    custom_headers: Dict[str, str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.custom_headers is None:
            self.custom_headers = {}


class ConfigurationManager:
    """Manages configuration for multiple API keys across services."""
    
    def __init__(self, config_path: str = "api_config"):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Directory path for configuration files
        """
        self.config_path = Path(config_path)
        self.config_path.mkdir(exist_ok=True)
        
        self.main_config_file = self.config_path / "config.json"
        self.profiles_dir = self.config_path / "profiles"
        self.profiles_dir.mkdir(exist_ok=True)
        
        self.secure_storage = SecureKeyStorage()
        
        # Load or initialize main configuration
        self.config = self._load_main_config()
    
    def _load_main_config(self) -> Dict:
        """Load the main configuration file."""
        if self.main_config_file.exists():
            with open(self.main_config_file, 'r') as f:
                return json.load(f)
        else:
            # Initialize with default configuration
            default_config = {
                'version': '1.0',
                'created': datetime.now().isoformat(),
                'profiles': {},
                'default_profile': 'default',
                'settings': {
                    'auto_rotate': False,
                    'rotation_days': 90,
                    'backup_enabled': True
                }
            }
            self._save_main_config(default_config)
            return default_config
    
    def _save_main_config(self, config: Dict):
        """Save the main configuration file."""
        with open(self.main_config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    def create_profile(self, profile_name: str, description: str = "") -> bool:
        """
        Create a new configuration profile.
        
        Args:
            profile_name: Name of the profile
            description: Profile description
        
        Returns:
            True if successful
        """
        profile_file = self.profiles_dir / f"{profile_name}.json"
        
        if profile_file.exists():
            print(f"Profile '{profile_name}' already exists")
            return False
        
        profile_data = {
            'name': profile_name,
            'description': description,
            'created': datetime.now().isoformat(),
            'api_keys': {},
            'environment_variables': {},
            'settings': {}
        }
        
        with open(profile_file, 'w') as f:
            json.dump(profile_data, f, indent=2)
        
        # Update main config
        self.config['profiles'][profile_name] = {
            'description': description,
            'created': profile_data['created']
        }
        self._save_main_config(self.config)
        
        return True
    
    def add_api_key(self, profile_name: str, key_config: APIKeyConfig, api_key: str) -> bool:
        """
        Add an API key to a profile.
        
        Args:
            profile_name: Name of the profile
            key_config: Configuration for the API key
            api_key: The actual API key value
        
        Returns:
            True if successful
        """
        profile_file = self.profiles_dir / f"{profile_name}.json"
        
        if not profile_file.exists():
            print(f"Profile '{profile_name}' not found")
            return False
        
        # Store the key securely
        storage_key_name = f"{profile_name}_{key_config.name}"
        metadata = {
            'profile': profile_name,
            'provider': key_config.provider.value,
            'environment': key_config.environment,
            'expiry': key_config.expiry
        }
        
        if not self.secure_storage.store_key(storage_key_name, api_key, metadata):
            return False
        
        # Load profile
        with open(profile_file, 'r') as f:
            profile_data = json.load(f)
        
        # Add key configuration (without the actual key)
        profile_data['api_keys'][key_config.name] = {
            'provider': key_config.provider.value,
            'environment': key_config.environment,
            'endpoint': key_config.endpoint,
            'version': key_config.version,
            'rate_limit': key_config.rate_limit,
            'expiry': key_config.expiry,
            'tags': key_config.tags,
            'custom_headers': key_config.custom_headers,
            'storage_key': storage_key_name,
            'added': datetime.now().isoformat()
        }
        
        # Save updated profile
        with open(profile_file, 'w') as f:
            json.dump(profile_data, f, indent=2)
        
        return True
    
    def get_api_key(self, profile_name: str, key_name: str) -> Optional[Dict]:
        """
        Retrieve an API key and its configuration.
        
        Args:
            profile_name: Name of the profile
            key_name: Name of the API key
        
        Returns:
            Dictionary with key value and configuration
        """
        profile_file = self.profiles_dir / f"{profile_name}.json"
        
        if not profile_file.exists():
            return None
        
        with open(profile_file, 'r') as f:
            profile_data = json.load(f)
        
        if key_name not in profile_data['api_keys']:
            return None
        
        key_config = profile_data['api_keys'][key_name]
        storage_key_name = key_config['storage_key']
        
        # Retrieve the actual key
        api_key = self.secure_storage.retrieve_key(storage_key_name)
        
        if api_key:
            return {
                'key': api_key,
                'config': key_config
            }
        
        return None
    
    def list_profiles(self) -> List[Dict]:
        """List all available profiles."""
        profiles = []
        
        for profile_name, profile_info in self.config['profiles'].items():
            profile_file = self.profiles_dir / f"{profile_name}.json"
            
            if profile_file.exists():
                with open(profile_file, 'r') as f:
                    profile_data = json.load(f)
                
                profiles.append({
                    'name': profile_name,
                    'description': profile_info.get('description', ''),
                    'created': profile_info.get('created'),
                    'num_keys': len(profile_data.get('api_keys', {}))
                })
        
        return profiles
    
    def list_keys_in_profile(self, profile_name: str) -> List[Dict]:
        """List all API keys in a profile (without exposing the actual keys)."""
        profile_file = self.profiles_dir / f"{profile_name}.json"
        
        if not profile_file.exists():
            return []
        
        with open(profile_file, 'r') as f:
            profile_data = json.load(f)
        
        keys = []
        for key_name, key_config in profile_data.get('api_keys', {}).items():
            keys.append({
                'name': key_name,
                'provider': key_config.get('provider'),
                'environment': key_config.get('environment'),
                'endpoint': key_config.get('endpoint'),
                'tags': key_config.get('tags', []),
                'added': key_config.get('added')
            })
        
        return keys
    
    def set_environment_variable(self, profile_name: str, var_name: str, var_value: str):
        """Set an environment variable for a profile."""
        profile_file = self.profiles_dir / f"{profile_name}.json"
        
        if not profile_file.exists():
            return False
        
        with open(profile_file, 'r') as f:
            profile_data = json.load(f)
        
        profile_data['environment_variables'][var_name] = var_value
        
        with open(profile_file, 'w') as f:
            json.dump(profile_data, f, indent=2)
        
        return True
    
    def load_profile_environment(self, profile_name: str) -> Dict[str, str]:
        """
        Load all API keys and environment variables for a profile.
        
        Returns:
            Dictionary of environment variables to set
        """
        profile_file = self.profiles_dir / f"{profile_name}.json"
        
        if not profile_file.exists():
            return {}
        
        with open(profile_file, 'r') as f:
            profile_data = json.load(f)
        
        env_vars = profile_data.get('environment_variables', {}).copy()
        
        # Add API keys to environment
        for key_name, key_config in profile_data.get('api_keys', {}).items():
            storage_key_name = key_config['storage_key']
            api_key = self.secure_storage.retrieve_key(storage_key_name)
            
            if api_key:
                # Generate environment variable name
                provider = key_config.get('provider', 'custom').upper()
                env_name = f"{provider}_API_KEY"
                
                # Handle multiple keys for same provider
                if env_name in env_vars:
                    env_name = f"{provider}_{key_name.upper()}_API_KEY"
                
                env_vars[env_name] = api_key
        
        return env_vars
    
    def export_profile(self, profile_name: str, output_file: str, include_keys: bool = False):
        """
        Export a profile configuration.
        
        Args:
            profile_name: Name of the profile to export
            output_file: Output file path
            include_keys: Whether to include encrypted keys
        """
        profile_file = self.profiles_dir / f"{profile_name}.json"
        
        if not profile_file.exists():
            print(f"Profile '{profile_name}' not found")
            return
        
        with open(profile_file, 'r') as f:
            profile_data = json.load(f)
        
        export_data = {
            'profile': profile_data,
            'exported': datetime.now().isoformat()
        }
        
        if include_keys:
            # Include encrypted key data
            storage_export = self.secure_storage.export_config(include_keys=True)
            export_data['secure_storage'] = storage_export
        
        # Determine output format from file extension
        output_path = Path(output_file)
        
        if output_path.suffix == '.yaml' or output_path.suffix == '.yml':
            with open(output_path, 'w') as f:
                yaml.dump(export_data, f, default_flow_style=False)
        else:
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
        
        print(f"Profile exported to {output_file}")
    
    def import_profile(self, import_file: str, profile_name: Optional[str] = None):
        """
        Import a profile configuration.
        
        Args:
            import_file: Path to import file
            profile_name: Optional new name for the profile
        """
        import_path = Path(import_file)
        
        if not import_path.exists():
            print(f"Import file '{import_file}' not found")
            return
        
        # Load import data
        if import_path.suffix == '.yaml' or import_path.suffix == '.yml':
            with open(import_path, 'r') as f:
                import_data = yaml.safe_load(f)
        else:
            with open(import_path, 'r') as f:
                import_data = json.load(f)
        
        profile_data = import_data.get('profile', {})
        
        if profile_name:
            profile_data['name'] = profile_name
        else:
            profile_name = profile_data.get('name', 'imported')
        
        # Create profile
        profile_file = self.profiles_dir / f"{profile_name}.json"
        
        with open(profile_file, 'w') as f:
            json.dump(profile_data, f, indent=2)
        
        # Update main config
        self.config['profiles'][profile_name] = {
            'description': profile_data.get('description', 'Imported profile'),
            'created': datetime.now().isoformat()
        }
        self._save_main_config(self.config)
        
        print(f"Profile '{profile_name}' imported successfully")
    
    def check_expiring_keys(self, days_before: int = 7) -> List[Dict]:
        """Check for API keys expiring soon across all profiles."""
        expiring_keys = []
        
        for profile_name in self.config['profiles']:
            profile_file = self.profiles_dir / f"{profile_name}.json"
            
            if profile_file.exists():
                with open(profile_file, 'r') as f:
                    profile_data = json.load(f)
                
                for key_name, key_config in profile_data.get('api_keys', {}).items():
                    expiry = key_config.get('expiry')
                    
                    if expiry:
                        try:
                            expiry_date = datetime.fromisoformat(expiry)
                            days_until = (expiry_date - datetime.now()).days
                            
                            if days_until <= days_before:
                                expiring_keys.append({
                                    'profile': profile_name,
                                    'key_name': key_name,
                                    'provider': key_config.get('provider'),
                                    'expiry': expiry,
                                    'days_until_expiry': days_until
                                })
                        except Exception:
                            pass
        
        return expiring_keys


# Convenience functions
def quick_setup(provider: str, api_key: str, profile: str = "default") -> bool:
    """Quick setup for common providers."""
    manager = ConfigurationManager()
    
    # Create default profile if needed
    if profile not in manager.config['profiles']:
        manager.create_profile(profile, "Default profile")
    
    # Create key configuration
    key_config = APIKeyConfig(
        name=f"{provider}_key",
        provider=ServiceProvider(provider.lower()),
        environment="production"
    )
    
    return manager.add_api_key(profile, key_config, api_key)


def load_environment(profile: str = "default"):
    """Load a profile's environment variables into the current process."""
    manager = ConfigurationManager()
    env_vars = manager.load_profile_environment(profile)
    
    for var_name, var_value in env_vars.items():
        os.environ[var_name] = var_value
    
    print(f"Loaded {len(env_vars)} environment variables from profile '{profile}'")