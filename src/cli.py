#!/usr/bin/env python3
"""
Secure Key Management CLI Tool

A command-line interface for managing API keys securely with encryption,
rotation, backup, and restore functionality.
"""

import os
import sys
import json
import getpass
import argparse
import secrets
import base64
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import click
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich import print as rprint

console = Console()

# Configuration paths
CONFIG_DIR = Path.home() / ".secure-keys"
KEYS_FILE = CONFIG_DIR / "keys.enc"
CONFIG_FILE = CONFIG_DIR / "config.json"
BACKUP_DIR = CONFIG_DIR / "backups"


class KeyManager:
    """Manages API keys with encryption and secure storage."""
    
    def __init__(self, master_password: Optional[str] = None):
        self.config_dir = CONFIG_DIR
        self.keys_file = KEYS_FILE
        self.config_file = CONFIG_FILE
        self.backup_dir = BACKUP_DIR
        
        # Create directories if they don't exist
        self.config_dir.mkdir(exist_ok=True)
        self.backup_dir.mkdir(exist_ok=True)
        
        # Initialize encryption
        self.cipher = None
        if master_password:
            self.unlock(master_password)
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _load_config(self) -> Dict:
        """Load configuration file."""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                return json.load(f)
        return {'salt': None, 'services': {}}
    
    def _save_config(self, config: Dict):
        """Save configuration file."""
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    def initialize(self, master_password: str):
        """Initialize the key manager with a master password."""
        config = self._load_config()
        
        if config['salt'] is None:
            # Generate new salt
            salt = os.urandom(16)
            config['salt'] = base64.b64encode(salt).decode()
            self._save_config(config)
        else:
            salt = base64.b64decode(config['salt'])
        
        # Derive key and create cipher
        key = self._derive_key(master_password, salt)
        self.cipher = Fernet(key)
        
        # Initialize empty keys file if it doesn't exist
        if not self.keys_file.exists():
            self._save_keys({})
    
    def unlock(self, master_password: str) -> bool:
        """Unlock the key manager with master password."""
        config = self._load_config()
        
        if config['salt'] is None:
            raise ValueError("Key manager not initialized. Run setup first.")
        
        salt = base64.b64decode(config['salt'])
        key = self._derive_key(master_password, salt)
        self.cipher = Fernet(key)
        
        # Test decryption
        try:
            self._load_keys()
            return True
        except Exception:
            self.cipher = None
            return False
    
    def _load_keys(self) -> Dict:
        """Load and decrypt keys from file."""
        if not self.cipher:
            raise ValueError("Key manager is locked")
        
        if not self.keys_file.exists():
            return {}
        
        with open(self.keys_file, 'rb') as f:
            encrypted_data = f.read()
        
        if not encrypted_data:
            return {}
        
        decrypted_data = self.cipher.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    
    def _save_keys(self, keys: Dict):
        """Encrypt and save keys to file."""
        if not self.cipher:
            raise ValueError("Key manager is locked")
        
        json_data = json.dumps(keys, indent=2)
        encrypted_data = self.cipher.encrypt(json_data.encode())
        
        with open(self.keys_file, 'wb') as f:
            f.write(encrypted_data)
    
    def add_key(self, service: str, key_name: str, key_value: str, metadata: Optional[Dict] = None):
        """Add a new API key."""
        keys = self._load_keys()
        
        if service not in keys:
            keys[service] = {}
        
        keys[service][key_name] = {
            'value': key_value,
            'created': datetime.now().isoformat(),
            'last_rotated': datetime.now().isoformat(),
            'metadata': metadata or {}
        }
        
        self._save_keys(keys)
        
        # Update service registry
        config = self._load_config()
        if service not in config['services']:
            config['services'][service] = {
                'created': datetime.now().isoformat(),
                'key_count': 0
            }
        config['services'][service]['key_count'] = len(keys[service])
        self._save_config(config)
    
    def remove_key(self, service: str, key_name: str) -> bool:
        """Remove an API key."""
        keys = self._load_keys()
        
        if service in keys and key_name in keys[service]:
            del keys[service][key_name]
            
            # Remove service if no keys left
            if not keys[service]:
                del keys[service]
            
            self._save_keys(keys)
            
            # Update service registry
            config = self._load_config()
            if service in keys:
                config['services'][service]['key_count'] = len(keys[service])
            else:
                del config['services'][service]
            self._save_config(config)
            
            return True
        return False
    
    def update_key(self, service: str, key_name: str, new_value: str):
        """Update an existing API key."""
        keys = self._load_keys()
        
        if service in keys and key_name in keys[service]:
            keys[service][key_name]['value'] = new_value
            keys[service][key_name]['last_rotated'] = datetime.now().isoformat()
            self._save_keys(keys)
            return True
        return False
    
    def get_key(self, service: str, key_name: str) -> Optional[str]:
        """Get a specific API key."""
        keys = self._load_keys()
        
        if service in keys and key_name in keys[service]:
            return keys[service][key_name]['value']
        return None
    
    def list_services(self) -> List[Dict]:
        """List all configured services."""
        config = self._load_config()
        keys = self._load_keys()
        
        services = []
        for service, info in config['services'].items():
            service_keys = keys.get(service, {})
            services.append({
                'name': service,
                'created': info['created'],
                'key_count': len(service_keys),
                'keys': list(service_keys.keys())
            })
        
        return services
    
    def rotate_key(self, service: str, key_name: str, new_value: Optional[str] = None) -> str:
        """Rotate an API key."""
        if new_value is None:
            # Generate a new random key
            new_value = secrets.token_urlsafe(32)
        
        if self.update_key(service, key_name, new_value):
            return new_value
        raise ValueError(f"Key {key_name} not found for service {service}")
    
    def backup(self, backup_name: Optional[str] = None) -> Path:
        """Create a backup of all keys."""
        if backup_name is None:
            backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        backup_path = self.backup_dir / f"{backup_name}.enc"
        
        # Copy encrypted keys file
        import shutil
        shutil.copy2(self.keys_file, backup_path)
        
        # Save backup metadata
        metadata = {
            'created': datetime.now().isoformat(),
            'services': self.list_services()
        }
        
        metadata_path = self.backup_dir / f"{backup_name}.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return backup_path
    
    def restore(self, backup_name: str) -> bool:
        """Restore keys from a backup."""
        backup_path = self.backup_dir / f"{backup_name}.enc"
        
        if not backup_path.exists():
            # Try without extension
            backup_path = self.backup_dir / backup_name
            if not backup_path.exists():
                return False
        
        # Create current backup before restore
        self.backup("pre_restore_auto")
        
        # Restore
        import shutil
        shutil.copy2(backup_path, self.keys_file)
        
        return True
    
    def list_backups(self) -> List[Dict]:
        """List all available backups."""
        backups = []
        
        for backup_file in self.backup_dir.glob("*.enc"):
            metadata_file = backup_file.with_suffix('.json')
            
            backup_info = {
                'name': backup_file.stem,
                'path': str(backup_file),
                'size': backup_file.stat().st_size,
                'created': datetime.fromtimestamp(backup_file.stat().st_mtime).isoformat()
            }
            
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                    backup_info['metadata'] = metadata
            
            backups.append(backup_info)
        
        return sorted(backups, key=lambda x: x['created'], reverse=True)


# CLI Commands using Click
@click.group()
@click.pass_context
def cli(ctx):
    """Secure Key Management CLI - Manage your API keys with encryption.
    
    Examples:
        cli.py setup                    # Initialize the key manager
        cli.py add github token         # Add a GitHub API key
        cli.py list                     # List all keys
        cli.py list github              # List GitHub keys only
        cli.py get github token         # Retrieve a specific key
        cli.py rotate github token      # Rotate a key
        cli.py remove github token      # Remove a key
    """
    ctx.ensure_object(dict)


@cli.command()
def setup():
    """Initialize the key manager with a master password."""
    console.print(Panel("[bold cyan]Secure Key Manager Setup[/bold cyan]"))
    
    # Check if already initialized
    config_file = CONFIG_FILE
    if config_file.exists():
        config = json.load(open(config_file))
        if config.get('salt'):
            if not Confirm.ask("[yellow]Key manager already initialized. Reinitialize?[/yellow]"):
                return
    
    # Get master password
    while True:
        password = Prompt.ask("Enter master password", password=True)
        confirm = Prompt.ask("Confirm master password", password=True)
        
        if password == confirm:
            if len(password) < 8:
                console.print("[red]Password must be at least 8 characters long[/red]")
                continue
            break
        else:
            console.print("[red]Passwords do not match[/red]")
    
    # Initialize
    manager = KeyManager()
    manager.initialize(password)
    
    console.print("[green]✓ Key manager initialized successfully![/green]")
    console.print("Use 'key-manager add' to add your first API key.")


@cli.command()
@click.argument('service')
@click.argument('key_name')
@click.option('--key-value', '-k', help='API key value (will prompt if not provided)')
@click.option('--metadata', '-m', help='Additional metadata as JSON')
def add(service, key_name, key_value, metadata):
    """Add a new API key."""
    manager = _get_manager()
    
    if not key_value:
        key_value = Prompt.ask(f"Enter API key for {service}/{key_name}", password=True)
    
    metadata_dict = {}
    if metadata:
        try:
            metadata_dict = json.loads(metadata)
        except json.JSONDecodeError:
            console.print("[red]Invalid JSON metadata[/red]")
            return
    
    manager.add_key(service, key_name, key_value, metadata_dict)
    console.print(f"[green]✓ Added key '{key_name}' for service '{service}'[/green]")


@cli.command()
@click.argument('service')
@click.argument('key_name')
def remove(service, key_name):
    """Remove an API key."""
    manager = _get_manager()
    
    if Confirm.ask(f"[yellow]Remove key '{key_name}' from service '{service}'?[/yellow]"):
        if manager.remove_key(service, key_name):
            console.print(f"[green]✓ Removed key '{key_name}' from service '{service}'[/green]")
        else:
            console.print(f"[red]Key '{key_name}' not found for service '{service}'[/red]")


@cli.command()
@click.argument('service')
@click.argument('key_name')
@click.option('--new-value', '-n', help='New API key value (will generate if not provided)')
def rotate(service, key_name, new_value):
    """Rotate an API key."""
    manager = _get_manager()
    
    try:
        new_key = manager.rotate_key(service, key_name, new_value)
        console.print(f"[green]✓ Rotated key '{key_name}' for service '{service}'[/green]")
        
        if not new_value:
            if Confirm.ask("[yellow]Show new generated key?[/yellow]"):
                console.print(f"New key: [cyan]{new_key}[/cyan]")
    except ValueError as e:
        console.print(f"[red]{e}[/red]")


@cli.command(name='list')
@click.argument('service', required=False)
def list_keys(service):
    """List configured services and keys.
    
    Usage:
        cli.py list              # List all services and keys
        cli.py list github       # List only github keys
    """
    manager = _get_manager()
    
    services = manager.list_services()
    
    if service:
        services = [s for s in services if s['name'] == service]
    
    if not services:
        console.print("[yellow]No services configured[/yellow]")
        return
    
    table = Table(title="Configured Services and Keys")
    table.add_column("Service", style="cyan")
    table.add_column("Keys", style="green")
    table.add_column("Created", style="yellow")
    
    for svc in services:
        table.add_row(
            svc['name'],
            ", ".join(svc['keys']),
            svc['created'][:10]
        )
    
    console.print(table)


@cli.command()
@click.argument('service')
@click.argument('key_name')
@click.option('--show', '-s', is_flag=True, help='Show the key value')
def get(service, key_name, show):
    """Get a specific API key."""
    manager = _get_manager()
    
    key_value = manager.get_key(service, key_name)
    
    if key_value:
        if show:
            console.print(f"[cyan]{key_value}[/cyan]")
        else:
            # Copy to clipboard if available
            try:
                import pyperclip
                pyperclip.copy(key_value)
                console.print(f"[green]✓ Key copied to clipboard[/green]")
            except ImportError:
                console.print("[yellow]Install 'pyperclip' to copy keys to clipboard[/yellow]")
                if Confirm.ask("Show key instead?"):
                    console.print(f"[cyan]{key_value}[/cyan]")
    else:
        console.print(f"[red]Key '{key_name}' not found for service '{service}'[/red]")


@cli.command()
@click.option('--name', '-n', help='Backup name (auto-generated if not provided)')
def backup(name):
    """Create a backup of all keys."""
    manager = _get_manager()
    
    backup_path = manager.backup(name)
    console.print(f"[green]✓ Backup created: {backup_path}[/green]")


@cli.command()
@click.argument('backup_name')
def restore(backup_name):
    """Restore keys from a backup."""
    manager = _get_manager()
    
    # List available backups if requested
    if backup_name == "list":
        backups = manager.list_backups()
        if not backups:
            console.print("[yellow]No backups available[/yellow]")
            return
        
        table = Table(title="Available Backups")
        table.add_column("Name", style="cyan")
        table.add_column("Created", style="yellow")
        table.add_column("Size", style="green")
        
        for backup in backups:
            table.add_row(
                backup['name'],
                backup['created'][:19],
                f"{backup['size']} bytes"
            )
        
        console.print(table)
        return
    
    if Confirm.ask(f"[yellow]Restore from backup '{backup_name}'? Current keys will be backed up first.[/yellow]"):
        if manager.restore(backup_name):
            console.print(f"[green]✓ Restored from backup '{backup_name}'[/green]")
        else:
            console.print(f"[red]Backup '{backup_name}' not found[/red]")


@cli.command()
def wizard():
    """Interactive setup wizard for new users."""
    console.print(Panel(
        "[bold cyan]Welcome to Secure Key Manager![/bold cyan]\n\n"
        "This wizard will help you set up the key manager and add your first API key.",
        title="Setup Wizard"
    ))
    
    # Initialize if needed
    if not CONFIG_FILE.exists() or not json.load(open(CONFIG_FILE)).get('salt'):
        console.print("\n[yellow]First, let's set up your master password.[/yellow]")
        console.print("This password will be used to encrypt all your API keys.")
        setup.invoke(click.Context(setup))
    
    # Add first key
    if Confirm.ask("\n[cyan]Would you like to add your first API key?[/cyan]"):
        service = Prompt.ask("Service name (e.g., github, aws, openai)")
        key_name = Prompt.ask("Key name (e.g., personal, work, prod)")
        key_value = Prompt.ask(f"API key value for {service}/{key_name}", password=True)
        
        manager = _get_manager()
        manager.add_key(service, key_name, key_value)
        
        console.print(f"\n[green]✓ Added key '{key_name}' for service '{service}'[/green]")
    
    console.print("\n[bold]Setup complete![/bold]")
    console.print("Use 'key-manager --help' to see all available commands.")


def _get_manager() -> KeyManager:
    """Get an unlocked KeyManager instance."""
    # Check if initialized
    if not CONFIG_FILE.exists():
        console.print("[red]Key manager not initialized. Run 'key-manager setup' first.[/red]")
        sys.exit(1)
    
    # Get master password
    password = getpass.getpass("Master password: ")
    
    manager = KeyManager()
    if not manager.unlock(password):
        console.print("[red]Invalid master password[/red]")
        sys.exit(1)
    
    return manager


if __name__ == '__main__':
    cli()