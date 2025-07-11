"""
Key Rotation System

This module provides automated and manual key rotation capabilities
with audit logging and rollback functionality.
"""

import os
import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Tuple
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
import logging

from secure_storage import SecureKeyStorage
from config_manager import ConfigurationManager, ServiceProvider


class RotationStatus(Enum):
    """Status of key rotation operation."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class RotationEvent:
    """Represents a key rotation event."""
    key_name: str
    profile: str
    provider: ServiceProvider
    old_key_hash: str
    new_key_hash: str
    timestamp: str
    status: RotationStatus
    reason: str
    error_message: Optional[str] = None
    rolled_back_at: Optional[str] = None


class KeyRotationManager:
    """Manages key rotation operations with audit trail and rollback."""
    
    def __init__(self, config_manager: ConfigurationManager, audit_dir: str = "rotation_audit"):
        """
        Initialize the key rotation manager.
        
        Args:
            config_manager: Configuration manager instance
            audit_dir: Directory for audit logs
        """
        self.config_manager = config_manager
        self.secure_storage = config_manager.secure_storage
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(exist_ok=True)
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Rotation callbacks for different providers
        self.rotation_callbacks: Dict[ServiceProvider, Callable] = {}
        
        # Active rotations tracking
        self.active_rotations: Dict[str, RotationEvent] = {}
        
        # Load rotation history
        self.rotation_history = self._load_rotation_history()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for rotation operations."""
        logger = logging.getLogger('KeyRotation')
        logger.setLevel(logging.INFO)
        
        # File handler
        log_file = self.audit_dir / 'rotation.log'
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def _hash_key(self, key: str) -> str:
        """Create a hash of the key for audit purposes (not the actual key)."""
        import hashlib
        return hashlib.sha256(key.encode()).hexdigest()[:16]
    
    def _load_rotation_history(self) -> List[RotationEvent]:
        """Load rotation history from audit files."""
        history_file = self.audit_dir / 'rotation_history.json'
        
        if not history_file.exists():
            return []
        
        try:
            with open(history_file, 'r') as f:
                data = json.load(f)
            
            events = []
            for event_data in data:
                event = RotationEvent(
                    key_name=event_data['key_name'],
                    profile=event_data['profile'],
                    provider=ServiceProvider(event_data['provider']),
                    old_key_hash=event_data['old_key_hash'],
                    new_key_hash=event_data['new_key_hash'],
                    timestamp=event_data['timestamp'],
                    status=RotationStatus(event_data['status']),
                    reason=event_data['reason'],
                    error_message=event_data.get('error_message'),
                    rolled_back_at=event_data.get('rolled_back_at')
                )
                events.append(event)
            
            return events
        except Exception as e:
            self.logger.error(f"Failed to load rotation history: {e}")
            return []
    
    def _save_rotation_history(self):
        """Save rotation history to audit file."""
        history_file = self.audit_dir / 'rotation_history.json'
        
        data = []
        for event in self.rotation_history:
            event_data = {
                'key_name': event.key_name,
                'profile': event.profile,
                'provider': event.provider.value,
                'old_key_hash': event.old_key_hash,
                'new_key_hash': event.new_key_hash,
                'timestamp': event.timestamp,
                'status': event.status.value,
                'reason': event.reason,
                'error_message': event.error_message,
                'rolled_back_at': event.rolled_back_at
            }
            data.append(event_data)
        
        with open(history_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def register_rotation_callback(self, provider: ServiceProvider, callback: Callable):
        """
        Register a callback function for rotating keys with a specific provider.
        
        Args:
            provider: The service provider
            callback: Function that takes old_key and returns new_key
        """
        self.rotation_callbacks[provider] = callback
        self.logger.info(f"Registered rotation callback for {provider.value}")
    
    def rotate_key(self, profile: str, key_name: str, new_key: Optional[str] = None,
                   reason: str = "manual", test_mode: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Rotate a specific API key.
        
        Args:
            profile: Profile name
            key_name: Key name
            new_key: New key value (if None, uses provider callback)
            reason: Reason for rotation
            test_mode: If True, validates but doesn't commit
        
        Returns:
            Tuple of (success, error_message)
        """
        rotation_id = f"{profile}_{key_name}_{int(time.time())}"
        
        try:
            # Get current key
            key_data = self.config_manager.get_api_key(profile, key_name)
            if not key_data:
                return False, f"Key '{key_name}' not found in profile '{profile}'"
            
            old_key = key_data['key']
            key_config = key_data['config']
            provider = ServiceProvider(key_config['provider'])
            
            # Generate new key if not provided
            if new_key is None:
                if provider not in self.rotation_callbacks:
                    return False, f"No rotation callback registered for {provider.value}"
                
                try:
                    new_key = self.rotation_callbacks[provider](old_key)
                except Exception as e:
                    return False, f"Failed to generate new key: {e}"
            
            # Create rotation event
            rotation_event = RotationEvent(
                key_name=key_name,
                profile=profile,
                provider=provider,
                old_key_hash=self._hash_key(old_key),
                new_key_hash=self._hash_key(new_key),
                timestamp=datetime.now().isoformat(),
                status=RotationStatus.IN_PROGRESS,
                reason=reason
            )
            
            self.active_rotations[rotation_id] = rotation_event
            self.logger.info(f"Starting rotation for {profile}/{key_name}")
            
            if test_mode:
                self.logger.info("Test mode: Rotation validated but not committed")
                del self.active_rotations[rotation_id]
                return True, None
            
            # Store backup of old key
            backup_key_name = f"{key_config['storage_key']}_backup_{int(time.time())}"
            self.secure_storage.store_key(backup_key_name, old_key, {
                'type': 'backup',
                'original_key': key_config['storage_key'],
                'rotation_id': rotation_id
            })
            
            # Perform rotation
            storage_key_name = key_config['storage_key']
            if not self.secure_storage.rotate_key(storage_key_name, new_key):
                raise Exception("Failed to update key in secure storage")
            
            # Update rotation event
            rotation_event.status = RotationStatus.COMPLETED
            self.rotation_history.append(rotation_event)
            self._save_rotation_history()
            
            # Clean up
            del self.active_rotations[rotation_id]
            
            self.logger.info(f"Successfully rotated key {profile}/{key_name}")
            return True, None
            
        except Exception as e:
            self.logger.error(f"Key rotation failed: {e}")
            
            # Update rotation event
            if rotation_id in self.active_rotations:
                rotation_event = self.active_rotations[rotation_id]
                rotation_event.status = RotationStatus.FAILED
                rotation_event.error_message = str(e)
                self.rotation_history.append(rotation_event)
                self._save_rotation_history()
                del self.active_rotations[rotation_id]
            
            return False, str(e)
    
    def rollback_rotation(self, profile: str, key_name: str) -> Tuple[bool, Optional[str]]:
        """
        Rollback the last rotation for a key.
        
        Returns:
            Tuple of (success, error_message)
        """
        try:
            # Find the last completed rotation for this key
            recent_rotation = None
            for event in reversed(self.rotation_history):
                if (event.profile == profile and 
                    event.key_name == key_name and 
                    event.status == RotationStatus.COMPLETED and
                    event.rolled_back_at is None):
                    recent_rotation = event
                    break
            
            if not recent_rotation:
                return False, "No recent rotation found to rollback"
            
            # Find backup key
            key_data = self.config_manager.get_api_key(profile, key_name)
            if not key_data:
                return False, f"Key '{key_name}' not found"
            
            storage_key_name = key_data['config']['storage_key']
            
            # Look for backup keys
            all_keys = self.secure_storage.list_keys()
            backup_key_name = None
            
            for key_info in all_keys:
                metadata = key_info.get('metadata', {})
                if (metadata.get('type') == 'backup' and
                    metadata.get('original_key') == storage_key_name):
                    backup_key_name = key_info['name']
                    break
            
            if not backup_key_name:
                return False, "No backup key found for rollback"
            
            # Retrieve backup key
            old_key = self.secure_storage.retrieve_key(backup_key_name)
            if not old_key:
                return False, "Failed to retrieve backup key"
            
            # Perform rollback
            if not self.secure_storage.rotate_key(storage_key_name, old_key):
                return False, "Failed to restore old key"
            
            # Update rotation event
            recent_rotation.rolled_back_at = datetime.now().isoformat()
            self._save_rotation_history()
            
            # Clean up backup
            self.secure_storage.delete_key(backup_key_name)
            
            self.logger.info(f"Successfully rolled back key {profile}/{key_name}")
            return True, None
            
        except Exception as e:
            self.logger.error(f"Rollback failed: {e}")
            return False, str(e)
    
    def auto_rotate_expiring_keys(self, days_before: int = 7, dry_run: bool = True) -> List[Dict]:
        """
        Automatically rotate keys that are expiring soon.
        
        Args:
            days_before: Days before expiry to trigger rotation
            dry_run: If True, only reports what would be rotated
        
        Returns:
            List of rotation results
        """
        expiring_keys = self.config_manager.check_expiring_keys(days_before)
        results = []
        
        for key_info in expiring_keys:
            profile = key_info['profile']
            key_name = key_info['key_name']
            
            if dry_run:
                results.append({
                    'profile': profile,
                    'key_name': key_name,
                    'action': 'would_rotate',
                    'days_until_expiry': key_info['days_until_expiry']
                })
            else:
                success, error = self.rotate_key(
                    profile, key_name, 
                    reason=f"auto_rotation_expiry_{key_info['days_until_expiry']}_days"
                )
                
                results.append({
                    'profile': profile,
                    'key_name': key_name,
                    'action': 'rotated' if success else 'failed',
                    'error': error,
                    'days_until_expiry': key_info['days_until_expiry']
                })
        
        return results
    
    def schedule_rotation(self, profile: str, key_name: str, 
                         rotation_date: datetime, reason: str = "scheduled"):
        """
        Schedule a key rotation for a future date.
        
        Args:
            profile: Profile name
            key_name: Key name
            rotation_date: When to rotate
            reason: Reason for rotation
        """
        schedule_file = self.audit_dir / 'rotation_schedule.json'
        
        # Load existing schedule
        schedule = []
        if schedule_file.exists():
            with open(schedule_file, 'r') as f:
                schedule = json.load(f)
        
        # Add new scheduled rotation
        schedule.append({
            'profile': profile,
            'key_name': key_name,
            'rotation_date': rotation_date.isoformat(),
            'reason': reason,
            'scheduled_at': datetime.now().isoformat()
        })
        
        # Save schedule
        with open(schedule_file, 'w') as f:
            json.dump(schedule, f, indent=2)
        
        self.logger.info(f"Scheduled rotation for {profile}/{key_name} on {rotation_date}")
    
    def get_rotation_history(self, profile: Optional[str] = None, 
                           key_name: Optional[str] = None) -> List[Dict]:
        """
        Get rotation history with optional filtering.
        
        Args:
            profile: Filter by profile
            key_name: Filter by key name
        
        Returns:
            List of rotation events
        """
        history = []
        
        for event in self.rotation_history:
            if profile and event.profile != profile:
                continue
            if key_name and event.key_name != key_name:
                continue
            
            history.append({
                'profile': event.profile,
                'key_name': event.key_name,
                'provider': event.provider.value,
                'timestamp': event.timestamp,
                'status': event.status.value,
                'reason': event.reason,
                'error_message': event.error_message,
                'rolled_back_at': event.rolled_back_at
            })
        
        return history
    
    def generate_rotation_report(self, days: int = 30) -> Dict:
        """
        Generate a report of rotation activities.
        
        Args:
            days: Number of days to include in report
        
        Returns:
            Report dictionary
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        
        report = {
            'period': f"Last {days} days",
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_rotations': 0,
                'successful': 0,
                'failed': 0,
                'rolled_back': 0
            },
            'by_provider': {},
            'by_reason': {},
            'failures': []
        }
        
        for event in self.rotation_history:
            event_date = datetime.fromisoformat(event.timestamp)
            
            if event_date < cutoff_date:
                continue
            
            report['summary']['total_rotations'] += 1
            
            # Status counts
            if event.status == RotationStatus.COMPLETED:
                report['summary']['successful'] += 1
            elif event.status == RotationStatus.FAILED:
                report['summary']['failed'] += 1
                report['failures'].append({
                    'profile': event.profile,
                    'key_name': event.key_name,
                    'timestamp': event.timestamp,
                    'error': event.error_message
                })
            
            if event.rolled_back_at:
                report['summary']['rolled_back'] += 1
            
            # By provider
            provider_name = event.provider.value
            if provider_name not in report['by_provider']:
                report['by_provider'][provider_name] = 0
            report['by_provider'][provider_name] += 1
            
            # By reason
            if event.reason not in report['by_reason']:
                report['by_reason'][event.reason] = 0
            report['by_reason'][event.reason] += 1
        
        return report


# Example rotation callbacks for different providers
def openai_rotation_callback(old_key: str) -> str:
    """Example callback for OpenAI key rotation."""
    # In a real implementation, this would call OpenAI's API
    # to generate a new key and revoke the old one
    import secrets
    return f"sk-{secrets.token_urlsafe(48)}"


def aws_rotation_callback(old_key: str) -> str:
    """Example callback for AWS key rotation."""
    # In a real implementation, this would use boto3
    # to create new access keys and delete old ones
    import secrets
    return f"AKIA{secrets.token_urlsafe(16).upper()}"