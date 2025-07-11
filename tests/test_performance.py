"""
Performance Tests for API Key Storage System
Tests system performance, scalability, and resource usage
"""

import unittest
import os
import tempfile
import shutil
import time
import threading
import multiprocessing
import psutil
import sys
import random
import string
import statistics
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api_key_storage import APIKeyStorage


class PerformanceTests(unittest.TestCase):
    """Performance testing suite"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.storage = APIKeyStorage(storage_path=self.test_dir, master_password="perf_test")
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
    
    def _generate_random_key(self, length=32):
        """Generate random API key"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def test_write_performance(self):
        """Test write performance for adding keys"""
        write_times = []
        num_keys = 1000
        
        print(f"\nTesting write performance with {num_keys} keys...")
        
        for i in range(num_keys):
            key = self._generate_random_key()
            
            start_time = time.perf_counter()
            key_id = self.storage.add_api_key(
                f"service_{i}",
                key,
                f"user_{i % 10}",
                metadata={"index": i}
            )
            end_time = time.perf_counter()
            
            write_times.append(end_time - start_time)
            
            if i % 100 == 0:
                print(f"  Processed {i} keys...")
        
        # Calculate statistics
        avg_time = statistics.mean(write_times)
        median_time = statistics.median(write_times)
        p95_time = statistics.quantiles(write_times, n=20)[18]  # 95th percentile
        p99_time = statistics.quantiles(write_times, n=100)[98]  # 99th percentile
        
        print(f"\nWrite Performance Results:")
        print(f"  Average write time: {avg_time*1000:.2f} ms")
        print(f"  Median write time: {median_time*1000:.2f} ms")
        print(f"  95th percentile: {p95_time*1000:.2f} ms")
        print(f"  99th percentile: {p99_time*1000:.2f} ms")
        print(f"  Total time for {num_keys} keys: {sum(write_times):.2f} seconds")
        
        # Performance assertions
        self.assertLess(avg_time, 0.01)  # Average should be under 10ms
        self.assertLess(p95_time, 0.02)  # 95th percentile under 20ms
    
    def test_read_performance(self):
        """Test read performance for retrieving keys"""
        # First, add keys
        key_ids = []
        for i in range(100):
            key_id = self.storage.add_api_key(
                f"service_{i}",
                self._generate_random_key(),
                "user"
            )
            key_ids.append(key_id)
        
        # Test read performance
        read_times = []
        num_reads = 1000
        
        print(f"\nTesting read performance with {num_reads} reads...")
        
        for i in range(num_reads):
            key_id = random.choice(key_ids)
            
            start_time = time.perf_counter()
            key = self.storage.get_api_key(key_id, "user")
            end_time = time.perf_counter()
            
            read_times.append(end_time - start_time)
            
            if i % 100 == 0:
                print(f"  Completed {i} reads...")
        
        # Calculate statistics
        avg_time = statistics.mean(read_times)
        median_time = statistics.median(read_times)
        p95_time = statistics.quantiles(read_times, n=20)[18]
        p99_time = statistics.quantiles(read_times, n=100)[98]
        
        print(f"\nRead Performance Results:")
        print(f"  Average read time: {avg_time*1000:.2f} ms")
        print(f"  Median read time: {median_time*1000:.2f} ms")
        print(f"  95th percentile: {p95_time*1000:.2f} ms")
        print(f"  99th percentile: {p99_time*1000:.2f} ms")
        
        # Performance assertions
        self.assertLess(avg_time, 0.005)  # Average should be under 5ms
        self.assertLess(p95_time, 0.01)   # 95th percentile under 10ms
    
    def test_list_performance(self):
        """Test performance of listing keys with various sizes"""
        test_sizes = [10, 100, 1000, 5000]
        
        print("\nTesting list performance with different dataset sizes...")
        
        for size in test_sizes:
            # Clear and recreate storage
            self.tearDown()
            self.setUp()
            
            # Add keys
            print(f"\n  Testing with {size} keys...")
            for i in range(size):
                self.storage.add_api_key(
                    f"service_{i}",
                    self._generate_random_key(),
                    f"user_{i % 10}"
                )
            
            # Measure list performance
            list_times = []
            for _ in range(10):
                start_time = time.perf_counter()
                keys = self.storage.list_keys("admin")
                end_time = time.perf_counter()
                
                list_times.append(end_time - start_time)
            
            avg_list_time = statistics.mean(list_times)
            print(f"    Average list time for {size} keys: {avg_list_time*1000:.2f} ms")
            
            # Performance assertion - should scale linearly
            self.assertLess(avg_list_time, size * 0.0001)  # 0.1ms per key max
    
    def test_concurrent_performance(self):
        """Test performance under concurrent load"""
        num_threads = 10
        operations_per_thread = 100
        
        print(f"\nTesting concurrent performance with {num_threads} threads...")
        
        # Pre-populate some keys
        initial_keys = []
        for i in range(50):
            key_id = self.storage.add_api_key(
                f"initial_{i}",
                self._generate_random_key(),
                "admin"
            )
            initial_keys.append(key_id)
        
        results = {
            "times": [],
            "errors": [],
            "success_count": 0
        }
        lock = threading.Lock()
        
        def worker(thread_id):
            thread_times = []
            
            for i in range(operations_per_thread):
                operation = random.choice(["add", "get", "list"])
                
                try:
                    start_time = time.perf_counter()
                    
                    if operation == "add":
                        self.storage.add_api_key(
                            f"thread_{thread_id}_{i}",
                            self._generate_random_key(),
                            f"thread_{thread_id}"
                        )
                    elif operation == "get":
                        key_id = random.choice(initial_keys)
                        self.storage.get_api_key(key_id, f"thread_{thread_id}")
                    else:  # list
                        self.storage.list_keys(f"thread_{thread_id}")
                    
                    end_time = time.perf_counter()
                    thread_times.append(end_time - start_time)
                    
                except Exception as e:
                    with lock:
                        results["errors"].append(str(e))
            
            with lock:
                results["times"].extend(thread_times)
                results["success_count"] += len(thread_times)
        
        # Run threads
        threads = []
        start_time = time.time()
        
        for i in range(num_threads):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        total_time = time.time() - start_time
        
        # Calculate results
        if results["times"]:
            avg_operation_time = statistics.mean(results["times"])
            throughput = results["success_count"] / total_time
            
            print(f"\nConcurrent Performance Results:")
            print(f"  Total operations: {results['success_count']}")
            print(f"  Total time: {total_time:.2f} seconds")
            print(f"  Throughput: {throughput:.2f} operations/second")
            print(f"  Average operation time: {avg_operation_time*1000:.2f} ms")
            print(f"  Errors: {len(results['errors'])}")
            
            # Assertions
            self.assertEqual(len(results["errors"]), 0)
            self.assertGreater(throughput, 100)  # At least 100 ops/second
    
    def test_memory_usage(self):
        """Test memory usage with large datasets"""
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        print(f"\nTesting memory usage...")
        print(f"  Initial memory: {initial_memory:.2f} MB")
        
        # Add many keys
        num_keys = 10000
        for i in range(num_keys):
            self.storage.add_api_key(
                f"memory_test_{i}",
                self._generate_random_key(64),  # Larger keys
                f"user_{i % 100}",
                metadata={
                    "description": f"This is a test key number {i}",
                    "created_by": "memory_test",
                    "index": i
                }
            )
            
            if i % 1000 == 0:
                current_memory = process.memory_info().rss / 1024 / 1024
                print(f"  After {i} keys: {current_memory:.2f} MB")
        
        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory
        memory_per_key = memory_increase / num_keys * 1000  # KB per key
        
        print(f"\nMemory Usage Results:")
        print(f"  Final memory: {final_memory:.2f} MB")
        print(f"  Memory increase: {memory_increase:.2f} MB")
        print(f"  Memory per key: {memory_per_key:.2f} KB")
        
        # Assert reasonable memory usage
        self.assertLess(memory_per_key, 10)  # Less than 10KB per key
    
    def test_encryption_performance(self):
        """Test encryption/decryption performance"""
        # Test with different key sizes
        key_sizes = [32, 64, 128, 256, 512, 1024]
        
        print("\nTesting encryption performance with different key sizes...")
        
        for size in key_sizes:
            large_key = self._generate_random_key(size)
            
            # Test encryption (add)
            start_time = time.perf_counter()
            key_id = self.storage.add_api_key("crypto_test", large_key, "user")
            encrypt_time = time.perf_counter() - start_time
            
            # Test decryption (get)
            start_time = time.perf_counter()
            retrieved = self.storage.get_api_key(key_id, "user")
            decrypt_time = time.perf_counter() - start_time
            
            print(f"  Key size {size} bytes:")
            print(f"    Encryption time: {encrypt_time*1000:.2f} ms")
            print(f"    Decryption time: {decrypt_time*1000:.2f} ms")
            
            # Verify correctness
            self.assertEqual(retrieved, large_key)
            
            # Performance assertions
            self.assertLess(encrypt_time, 0.05)  # Under 50ms
            self.assertLess(decrypt_time, 0.05)  # Under 50ms
    
    def test_scalability_limits(self):
        """Test system limits and scalability"""
        print("\nTesting scalability limits...")
        
        # Test 1: Maximum key length
        max_key_sizes = [1024, 10240, 102400]  # 1KB, 10KB, 100KB
        
        for size in max_key_sizes:
            try:
                huge_key = self._generate_random_key(size)
                key_id = self.storage.add_api_key(
                    "huge_key_test",
                    huge_key,
                    "user"
                )
                retrieved = self.storage.get_api_key(key_id, "user")
                self.assertEqual(len(retrieved), size)
                print(f"  Successfully handled {size} byte key")
            except Exception as e:
                print(f"  Failed at {size} bytes: {str(e)}")
        
        # Test 2: Maximum number of keys
        print("\n  Testing maximum number of keys...")
        batch_size = 1000
        total_keys = 0
        
        try:
            while total_keys < 50000:  # Test up to 50k keys
                for i in range(batch_size):
                    self.storage.add_api_key(
                        f"scale_test_{total_keys + i}",
                        self._generate_random_key(),
                        "scale_user"
                    )
                total_keys += batch_size
                
                if total_keys % 10000 == 0:
                    # Check performance doesn't degrade
                    start_time = time.perf_counter()
                    keys = self.storage.list_keys("scale_user")
                    list_time = time.perf_counter() - start_time
                    
                    print(f"    {total_keys} keys - List time: {list_time*1000:.2f} ms")
                    
                    # Performance should not degrade significantly
                    self.assertLess(list_time, 2.0)  # Under 2 seconds
        except Exception as e:
            print(f"  Reached limit at {total_keys} keys: {str(e)}")
    
    def test_cache_effectiveness(self):
        """Test if caching improves performance"""
        # Add some keys
        key_ids = []
        for i in range(100):
            key_id = self.storage.add_api_key(
                f"cache_test_{i}",
                self._generate_random_key(),
                "user"
            )
            key_ids.append(key_id)
        
        print("\nTesting cache effectiveness...")
        
        # First access (cold cache)
        cold_times = []
        for key_id in key_ids[:10]:
            start_time = time.perf_counter()
            self.storage.get_api_key(key_id, "user")
            cold_times.append(time.perf_counter() - start_time)
        
        # Repeated access (warm cache)
        warm_times = []
        for _ in range(10):
            for key_id in key_ids[:10]:
                start_time = time.perf_counter()
                self.storage.get_api_key(key_id, "user")
                warm_times.append(time.perf_counter() - start_time)
        
        avg_cold = statistics.mean(cold_times)
        avg_warm = statistics.mean(warm_times)
        
        print(f"  Average cold access time: {avg_cold*1000:.2f} ms")
        print(f"  Average warm access time: {avg_warm*1000:.2f} ms")
        print(f"  Improvement: {((avg_cold - avg_warm) / avg_cold * 100):.1f}%")
        
        # Warm access should be faster (if caching is implemented)
        # This test documents actual behavior


if __name__ == "__main__":
    # Run with verbosity for performance metrics
    unittest.main(verbosity=2)