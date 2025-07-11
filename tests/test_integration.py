"""
Integration Tests for API Key Storage System
Tests complete workflows and system integration
"""

import unittest
import os
import tempfile
import shutil
import json
import time
from datetime import datetime, timedelta
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api_key_storage import APIKeyStorage


class IntegrationTests(unittest.TestCase):
    """Integration testing suite for complete workflows"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.storage = APIKeyStorage(storage_path=self.test_dir, master_password="integration_test")
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
    
    def test_complete_key_lifecycle(self):
        """Test complete lifecycle: create, use, rotate, revoke"""
        # 1. Create API key
        service = "github"
        original_key = "ghp_1234567890abcdef"
        user = "developer1"
        
        key_id = self.storage.add_api_key(
            service=service,
            api_key=original_key,
            user=user,
            metadata={"environment": "production", "version": "1.0"}
        )
        
        self.assertIsNotNone(key_id)
        
        # 2. Use the key multiple times
        for i in range(5):
            retrieved_key = self.storage.get_api_key(key_id, user)
            self.assertEqual(retrieved_key, original_key)
            time.sleep(0.1)  # Simulate real usage
        
        # 3. List keys and verify metadata
        keys_list = self.storage.list_keys(user)
        self.assertEqual(len(keys_list), 1)
        
        key_info = keys_list[0]
        self.assertEqual(key_info["service"], service)
        self.assertEqual(key_info["access_count"], 5)
        self.assertIsNotNone(key_info["last_accessed"])
        
        # 4. Rotate the key
        new_key = "ghp_0987654321fedcba"
        rotation_success = self.storage.rotate_key(key_id, new_key, user)
        self.assertTrue(rotation_success)
        
        # 5. Verify old key is revoked
        old_key_access = self.storage.get_api_key(key_id, user)
        self.assertIsNone(old_key_access)
        
        # 6. Verify new key works
        all_keys = self.storage.list_keys(user)
        active_keys = [k for k in all_keys if k["active"]]
        self.assertEqual(len(active_keys), 1)
        
        new_key_id = active_keys[0]["key_id"]
        retrieved_new_key = self.storage.get_api_key(new_key_id, user)
        self.assertEqual(retrieved_new_key, new_key)
        
        # 7. Check audit trail
        audit_log = self.storage.export_audit_log()
        self.assertIn("Added API key", audit_log)
        self.assertIn("Accessed API key", audit_log)
        self.assertIn("Rotated key", audit_log)
        self.assertIn("Revoked API key", audit_log)
    
    def test_multi_user_scenario(self):
        """Test multiple users with different keys"""
        users = ["alice", "bob", "charlie"]
        services = ["aws", "github", "stripe"]
        keys_map = {}
        
        # Each user adds keys for different services
        for user in users:
            keys_map[user] = {}
            for service in services:
                key = f"{service}_key_for_{user}_secret123"
                key_id = self.storage.add_api_key(service, key, user)
                keys_map[user][service] = {"key_id": key_id, "key": key}
        
        # Verify each user can access their keys
        for user in users:
            user_keys = self.storage.list_keys(user)
            # Should see all keys (9 total) but filtered by implementation if needed
            self.assertGreaterEqual(len(user_keys), 3)
            
            # Access each user's keys
            for service in services:
                key_data = keys_map[user][service]
                retrieved = self.storage.get_api_key(key_data["key_id"], user)
                self.assertEqual(retrieved, key_data["key"])
        
        # Test cross-user access (should work in this implementation)
        alice_key_id = keys_map["alice"]["aws"]["key_id"]
        bob_access = self.storage.get_api_key(alice_key_id, "bob")
        self.assertIsNotNone(bob_access)  # In production, this might be restricted
    
    def test_persistence_across_restarts(self):
        """Test that data persists across system restarts"""
        # Add some keys
        keys_data = [
            ("service1", "key1_secret", "user1", {"env": "prod"}),
            ("service2", "key2_secret", "user2", {"env": "dev"}),
            ("service3", "key3_secret", "user1", {"env": "staging"})
        ]
        
        key_ids = []
        for service, key, user, metadata in keys_data:
            key_id = self.storage.add_api_key(service, key, user, metadata)
            key_ids.append(key_id)
            # Access each key to update stats
            self.storage.get_api_key(key_id, user)
        
        # Simulate system restart by creating new instance
        del self.storage
        new_storage = APIKeyStorage(storage_path=self.test_dir, master_password="integration_test")
        
        # Verify all data is preserved
        for i, (service, key, user, metadata) in enumerate(keys_data):
            retrieved_key = new_storage.get_api_key(key_ids[i], user)
            self.assertEqual(retrieved_key, key)
            
            # Check metadata persistence
            keys_list = new_storage.list_keys(user)
            key_info = next(k for k in keys_list if k["key_id"] == key_ids[i])
            self.assertEqual(key_info["service"], service)
            self.assertEqual(key_info["access_count"], 2)  # 1 before + 1 after restart
    
    def test_key_expiry_workflow(self):
        """Test workflow for handling expired keys"""
        # Manually create keys with old timestamps
        old_key_id = self.storage.add_api_key("old_service", "old_key", "user")
        
        # Manually modify the creation date (hack for testing)
        self.storage.keys_data[old_key_id]["created_at"] = (
            datetime.now() - timedelta(days=100)
        ).isoformat()
        self.storage._save_keys()
        
        # Add a recent key
        new_key_id = self.storage.add_api_key("new_service", "new_key", "user")
        
        # Check for expired keys (90 days)
        expired_keys = self.storage.check_key_expiry(days=90)
        
        self.assertEqual(len(expired_keys), 1)
        self.assertEqual(expired_keys[0]["key_id"], old_key_id)
        self.assertGreater(expired_keys[0]["days_old"], 90)
        
        # Verify new key is not in expired list
        expired_key_ids = [k["key_id"] for k in expired_keys]
        self.assertNotIn(new_key_id, expired_key_ids)
    
    def test_error_recovery(self):
        """Test system recovery from various error conditions"""
        # Test 1: Corrupted encrypted data
        key_id = self.storage.add_api_key("test", "test_key", "user")
        
        # Corrupt the encrypted file
        with open(self.storage.keys_file, 'r') as f:
            data = json.load(f)
        
        # Corrupt one entry
        if data:
            first_key = list(data.keys())[0]
            data[first_key] = "corrupted_data"
        
        with open(self.storage.keys_file, 'w') as f:
            json.dump(data, f)
        
        # Try to load with new instance
        with self.assertRaises(Exception):
            corrupted_storage = APIKeyStorage(
                storage_path=self.test_dir, 
                master_password="integration_test"
            )
        
        # Test 2: Missing master key file (if using file-based key)
        test_dir2 = tempfile.mkdtemp()
        storage2 = APIKeyStorage(storage_path=test_dir2)  # No password, uses file
        storage2.add_api_key("test", "test_key", "user")
        
        # Remove master key file
        master_key_file = os.path.join(test_dir2, ".master_key")
        if os.path.exists(master_key_file):
            os.remove(master_key_file)
        
        # Try to load - should fail
        with self.assertRaises(Exception):
            storage3 = APIKeyStorage(storage_path=test_dir2)
        
        shutil.rmtree(test_dir2)
    
    def test_bulk_operations(self):
        """Test system performance with bulk operations"""
        # Add 100 keys
        start_time = time.time()
        key_ids = []
        
        for i in range(100):
            key_id = self.storage.add_api_key(
                f"service_{i}",
                f"api_key_secret_{i}",
                f"user_{i % 10}",  # 10 different users
                metadata={"index": i, "batch": "bulk_test"}
            )
            key_ids.append(key_id)
        
        add_time = time.time() - start_time
        self.assertLess(add_time, 5.0)  # Should complete in under 5 seconds
        
        # List all keys
        start_time = time.time()
        all_keys = self.storage.list_keys("admin")
        list_time = time.time() - start_time
        
        self.assertEqual(len(all_keys), 100)
        self.assertLess(list_time, 1.0)  # Listing should be fast
        
        # Access 50 random keys
        import random
        random_keys = random.sample(key_ids, 50)
        
        start_time = time.time()
        for key_id in random_keys:
            key = self.storage.get_api_key(key_id, "admin")
            self.assertIsNotNone(key)
        
        access_time = time.time() - start_time
        self.assertLess(access_time, 2.0)  # Should be reasonably fast
        
        # Bulk revocation
        start_time = time.time()
        for key_id in key_ids[:50]:  # Revoke first 50
            self.storage.revoke_key(key_id, "admin")
        
        revoke_time = time.time() - start_time
        self.assertLess(revoke_time, 3.0)
        
        # Verify revocations
        active_keys = [k for k in self.storage.list_keys("admin") if k["active"]]
        self.assertEqual(len(active_keys), 50)
    
    def test_concurrent_modifications(self):
        """Test handling of concurrent modifications"""
        import threading
        
        # Add initial keys
        base_keys = []
        for i in range(10):
            key_id = self.storage.add_api_key(f"service_{i}", f"key_{i}", "user")
            base_keys.append(key_id)
        
        results = {"errors": [], "success": 0}
        
        def modifier_thread(thread_id):
            try:
                # Each thread tries to modify keys
                for i in range(5):
                    # Add new key
                    self.storage.add_api_key(
                        f"thread_{thread_id}_service_{i}",
                        f"thread_{thread_id}_key_{i}",
                        f"thread_{thread_id}"
                    )
                    
                    # Access random existing key
                    if base_keys:
                        key_id = random.choice(base_keys)
                        self.storage.get_api_key(key_id, f"thread_{thread_id}")
                    
                    # List keys
                    self.storage.list_keys(f"thread_{thread_id}")
                    
                results["success"] += 1
            except Exception as e:
                results["errors"].append(f"Thread {thread_id}: {str(e)}")
        
        # Run concurrent threads
        threads = []
        for i in range(10):
            t = threading.Thread(target=modifier_thread, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Verify no errors
        self.assertEqual(len(results["errors"]), 0)
        self.assertEqual(results["success"], 10)
        
        # Verify final state is consistent
        final_keys = self.storage.list_keys("admin")
        self.assertEqual(len(final_keys), 60)  # 10 initial + 50 from threads


class APIIntegrationTests(unittest.TestCase):
    """Test integration with external APIs (mocked)"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.storage = APIKeyStorage(storage_path=self.test_dir)
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_api_key_formats(self):
        """Test handling of various API key formats"""
        # Different API key formats
        test_keys = [
            # Service, Key, Description
            ("github", "ghp_16CharacterToken1234567890abcdef", "GitHub Personal Access Token"),
            ("aws", "AKIAIOSFODNN7EXAMPLE", "AWS Access Key ID"),
            ("stripe", "sk_test_4eC39HqLyjWDarjtT1zdp7dc0000", "Stripe Secret Key"),
            ("openai", "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz", "OpenAI API Key"),
            ("sendgrid", "SG.abcdefghijklmnop.qrstuvwxyz123456789", "SendGrid API Key"),
            ("jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "JWT Token"),
        ]
        
        # Store all key formats
        stored_keys = {}
        for service, key, description in test_keys:
            key_id = self.storage.add_api_key(
                service=service,
                api_key=key,
                user="api_tester",
                metadata={"description": description, "format_test": True}
            )
            stored_keys[service] = (key_id, key)
        
        # Retrieve and verify all keys
        for service, (key_id, original_key) in stored_keys.items():
            retrieved = self.storage.get_api_key(key_id, "api_tester")
            self.assertEqual(retrieved, original_key)
            
        # Verify listing shows all services
        all_keys = self.storage.list_keys("api_tester")
        self.assertEqual(len(all_keys), len(test_keys))
        
        services_found = {k["service"] for k in all_keys}
        expected_services = {k[0] for k in test_keys}
        self.assertEqual(services_found, expected_services)


if __name__ == "__main__":
    unittest.main()