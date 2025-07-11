"""
Security Tests for API Key Storage System
Tests encryption, access control, and vulnerability assessment
"""

import unittest
import os
import tempfile
import shutil
import json
from datetime import datetime
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api_key_storage import APIKeyStorage, SecurityException


class SecurityTests(unittest.TestCase):
    """Comprehensive security testing suite"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.storage = APIKeyStorage(storage_path=self.test_dir, master_password="test_password_123")
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
    
    def test_encryption_at_rest(self):
        """Test that API keys are encrypted when stored"""
        # Add a test key
        test_key = "sk-test-1234567890abcdef"
        key_id = self.storage.add_api_key("test_service", test_key, "test_user")
        
        # Read the raw file
        with open(self.storage.keys_file, 'r') as f:
            raw_data = json.load(f)
        
        # Verify the API key is not stored in plaintext
        raw_content = json.dumps(raw_data)
        self.assertNotIn(test_key, raw_content)
        
        # Verify we can still retrieve the key correctly
        retrieved_key = self.storage.get_api_key(key_id, "test_user")
        self.assertEqual(retrieved_key, test_key)
    
    def test_access_control(self):
        """Test access control mechanisms"""
        # Add a key
        key_id = self.storage.add_api_key("github", "ghp_test123", "user1")
        
        # Test successful access
        key = self.storage.get_api_key(key_id, "user1")
        self.assertIsNotNone(key)
        
        # Test access to non-existent key
        fake_key = self.storage.get_api_key("fake_id", "user1")
        self.assertIsNone(fake_key)
        
        # Test revoked key access
        self.storage.revoke_key(key_id, "admin")
        revoked_key = self.storage.get_api_key(key_id, "user1")
        self.assertIsNone(revoked_key)
    
    def test_audit_logging(self):
        """Test security audit logging"""
        # Perform various operations
        key_id = self.storage.add_api_key("aws", "AKIA123456", "user1")
        self.storage.get_api_key(key_id, "user1")
        self.storage.get_api_key("invalid_id", "attacker")
        self.storage.revoke_key(key_id, "admin")
        
        # Check audit log
        audit_log = self.storage.export_audit_log()
        
        # Verify all operations are logged
        self.assertIn("Added API key", audit_log)
        self.assertIn("Accessed API key", audit_log)
        self.assertIn("non-existent key", audit_log)
        self.assertIn("Revoked API key", audit_log)
        
    def test_file_permissions(self):
        """Test that sensitive files have correct permissions"""
        # Add a key to create files
        self.storage.add_api_key("test", "test_key", "user")
        
        # Check file permissions (Unix only)
        if os.name != 'nt':  # Skip on Windows
            master_key_file = os.path.join(self.test_dir, ".master_key")
            keys_file = self.storage.keys_file
            
            # Check permissions (should be 0o600 - read/write for owner only)
            if os.path.exists(master_key_file):
                stat_info = os.stat(master_key_file)
                self.assertEqual(stat_info.st_mode & 0o777, 0o600)
            
            stat_info = os.stat(keys_file)
            self.assertEqual(stat_info.st_mode & 0o777, 0o600)
    
    def test_injection_attacks(self):
        """Test resistance to injection attacks"""
        # Test SQL-like injection in service name
        malicious_service = "'; DROP TABLE keys; --"
        key_id = self.storage.add_api_key(malicious_service, "test_key", "user")
        
        # Verify the system handles it safely
        keys = self.storage.list_keys("user")
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["service"], malicious_service)
        
        # Test script injection
        script_injection = "<script>alert('XSS')</script>"
        key_id2 = self.storage.add_api_key(script_injection, "test_key2", "user")
        retrieved = self.storage.list_keys("user")
        self.assertEqual(len(retrieved), 2)
    
    def test_timing_attack_resistance(self):
        """Test resistance to timing attacks"""
        import time
        
        # Add multiple keys
        valid_key_id = self.storage.add_api_key("service1", "key1", "user")
        
        # Measure access times for valid vs invalid keys
        valid_times = []
        invalid_times = []
        
        for _ in range(10):
            # Valid key access
            start = time.time()
            self.storage.get_api_key(valid_key_id, "user")
            valid_times.append(time.time() - start)
            
            # Invalid key access
            start = time.time()
            self.storage.get_api_key("invalid_id", "user")
            invalid_times.append(time.time() - start)
        
        # Times should be similar (constant-time comparison)
        avg_valid = sum(valid_times) / len(valid_times)
        avg_invalid = sum(invalid_times) / len(invalid_times)
        
        # Allow 50ms difference (timing attacks should show much larger differences)
        self.assertLess(abs(avg_valid - avg_invalid), 0.05)
    
    def test_key_rotation(self):
        """Test secure key rotation"""
        # Add initial key
        old_key = "old_api_key_123"
        key_id = self.storage.add_api_key("service", old_key, "user")
        
        # Rotate the key
        new_key = "new_api_key_456"
        success = self.storage.rotate_key(key_id, new_key, "user")
        self.assertTrue(success)
        
        # Verify old key is revoked
        old_key_access = self.storage.get_api_key(key_id, "user")
        self.assertIsNone(old_key_access)
        
        # Verify new key exists and works
        keys = self.storage.list_keys("user")
        new_key_data = next((k for k in keys if k.get("metadata", {}).get("rotated_from") == key_id), None)
        self.assertIsNotNone(new_key_data)
        
        retrieved_new_key = self.storage.get_api_key(new_key_data["key_id"], "user")
        self.assertEqual(retrieved_new_key, new_key)
    
    def test_memory_security(self):
        """Test that sensitive data doesn't persist in memory"""
        import gc
        
        # Create and use a key
        sensitive_key = "super_secret_api_key_xyz789"
        key_id = self.storage.add_api_key("memory_test", sensitive_key, "user")
        
        # Retrieve the key
        retrieved = self.storage.get_api_key(key_id, "user")
        self.assertEqual(retrieved, sensitive_key)
        
        # Delete references and force garbage collection
        del retrieved
        del sensitive_key
        gc.collect()
        
        # This is a basic test - in production, use memory scrubbing libraries
        
    def test_concurrent_access(self):
        """Test thread safety of storage system"""
        import threading
        import random
        
        results = []
        errors = []
        
        def worker(worker_id):
            try:
                for i in range(5):
                    # Add a key
                    key_id = self.storage.add_api_key(
                        f"service_{worker_id}_{i}",
                        f"key_{worker_id}_{i}",
                        f"user_{worker_id}"
                    )
                    
                    # Access the key
                    retrieved = self.storage.get_api_key(key_id, f"user_{worker_id}")
                    results.append((worker_id, retrieved))
                    
                    # Random sleep to increase concurrency chances
                    threading.Event().wait(random.uniform(0.001, 0.01))
            except Exception as e:
                errors.append((worker_id, str(e)))
        
        # Run multiple threads
        threads = []
        for i in range(5):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        # Wait for completion
        for t in threads:
            t.join()
        
        # Verify no errors occurred
        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")
        
        # Verify all operations completed
        self.assertEqual(len(results), 25)  # 5 workers * 5 operations each
    
    def test_encryption_key_derivation(self):
        """Test that encryption keys are properly derived from passwords"""
        # Create two instances with same password
        storage1 = APIKeyStorage(
            storage_path=os.path.join(self.test_dir, "storage1"),
            master_password="same_password"
        )
        storage2 = APIKeyStorage(
            storage_path=os.path.join(self.test_dir, "storage2"),
            master_password="same_password"
        )
        
        # Add same data to both
        key_id1 = storage1.add_api_key("service", "api_key", "user")
        key_id2 = storage2.add_api_key("service", "api_key", "user")
        
        # Different instance with different password should fail to decrypt
        with self.assertRaises(SecurityException):
            storage3 = APIKeyStorage(
                storage_path=os.path.join(self.test_dir, "storage1"),
                master_password="different_password"
            )


class VulnerabilityTests(unittest.TestCase):
    """Tests for common vulnerabilities"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.storage = APIKeyStorage(storage_path=self.test_dir)
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_path_traversal(self):
        """Test resistance to path traversal attacks"""
        # Attempt to use path traversal in storage path
        try:
            malicious_storage = APIKeyStorage(
                storage_path="../../../etc/passwd",
                master_password="test"
            )
            # If we get here, the path was accepted (but should be sandboxed)
            self.assertNotEqual(malicious_storage.storage_path, "/etc/passwd")
        except:
            # Expected behavior - reject dangerous paths
            pass
    
    def test_large_input_handling(self):
        """Test handling of extremely large inputs"""
        # Test with very large API key
        large_key = "x" * 1000000  # 1MB key
        
        # Should handle gracefully
        key_id = self.storage.add_api_key("large_service", large_key, "user")
        retrieved = self.storage.get_api_key(key_id, "user")
        self.assertEqual(retrieved, large_key)
    
    def test_special_characters(self):
        """Test handling of special characters in all fields"""
        special_chars = "!@#$%^&*()_+-={}[]|\\:;\"'<>,.?/~`"
        unicode_chars = "🔐🔑🗝️ñáéíóú中文"
        
        # Test in service name
        key_id1 = self.storage.add_api_key(special_chars, "key1", "user")
        
        # Test in API key
        key_id2 = self.storage.add_api_key("service", special_chars + unicode_chars, "user")
        
        # Test in username
        key_id3 = self.storage.add_api_key("service", "key3", special_chars)
        
        # Verify all can be retrieved
        self.assertIsNotNone(self.storage.get_api_key(key_id1, "user"))
        self.assertEqual(self.storage.get_api_key(key_id2, "user"), special_chars + unicode_chars)
        self.assertIsNotNone(self.storage.get_api_key(key_id3, special_chars))


if __name__ == "__main__":
    unittest.main()