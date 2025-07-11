# 🔐 Secure API Key Storage

A production-ready, enterprise-grade secure storage system for API keys with support for GitHub, Claude, and other services. Built with security-first principles and comprehensive encryption.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![Security](https://img.shields.io/badge/security-AES--256--GCM-green)
![License](https://img.shields.io/badge/license-MIT-purple)
![Tests](https://img.shields.io/badge/tests-30%2B-brightgreen)

## 🌟 Features

### Core Security Features
- **🔒 AES-256-GCM Encryption** - Military-grade authenticated encryption
- **🔑 PBKDF2 Key Derivation** - 100,000 iterations for master key protection
- **📝 Comprehensive Audit Logging** - Track all key operations
- **🔄 Automated Key Rotation** - Built-in rotation with rollback support
- **🛡️ Memory Protection** - Secure string handling and anti-debugging measures

### Service Integrations
- **GitHub** - Full API integration with token validation
- **Claude/Anthropic** - Complete Claude API support
- **OpenAI** - GPT model access
- **AWS** - AWS service authentication
- **Generic** - Support for any API service

### User Interfaces
- **CLI Tool** - Feature-rich command-line interface
- **Python Library** - Programmatic API for automation
- **Interactive Mode** - REPL with auto-completion
- **Web Dashboard** - Modern Next.js dashboard with real-time analytics

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/murr2k/secure-api-key-storage.git
cd secure-api-key-storage

# Install dependencies
pip install -r requirements.txt

# Set up master key (use a strong password)
export API_KEY_MASTER="your-secure-master-key"
```

### Basic Usage

```bash
# Store an API key
python src/cli.py store github_token --service github --value "ghp_yourtoken"

# Retrieve a key
python src/cli.py get github_token

# List all keys
python src/cli.py list

# Rotate a key
python src/cli.py rotate github_token
```

### Python API Usage

```python
from src.secure_storage import SecureKeyStorage
from src.integrations.github_integration import GitHubIntegration

# Initialize storage
storage = SecureKeyStorage()

# Store a key
storage.store_key("github_token", "ghp_yourtoken", service="github")

# Use with integration
github = GitHubIntegration(storage)
user_info = github.get_user_info()
```

### Web Dashboard

The project includes a modern web dashboard for visual key management:

```bash
# Start the backend API
cd dashboard/backend
./start.sh  # or: uvicorn main:app --reload

# Start the frontend (in another terminal)
cd dashboard/frontend
npm install
npm run dev
```

Access the dashboard at http://localhost:3000

Features:
- 📊 Real-time analytics and statistics
- 🔑 Visual key management interface
- 📝 Live audit log streaming
- 📱 Responsive design for all devices
- 🔐 JWT authentication with secure sessions

## 📁 Project Structure

```
secure-api-key-storage/
├── src/
│   ├── secure_storage.py      # Core encryption and storage
│   ├── config_manager.py      # Configuration management
│   ├── key_rotation.py        # Key rotation system
│   ├── cli.py                 # Command-line interface
│   └── integrations/          # Service integrations
│       ├── base_integration.py
│       ├── github_integration.py
│       ├── claude_integration.py
│       └── generic_integration.py
├── tests/                     # Comprehensive test suite
│   ├── test_security.py       # Security tests
│   ├── test_integration.py    # Integration tests
│   └── test_performance.py    # Performance benchmarks
├── dashboard/                 # Web dashboard
│   ├── backend/               # FastAPI backend
│   ├── frontend/              # Next.js frontend
│   └── docs/                  # Dashboard documentation
├── examples/                  # Usage examples
├── docs/                      # Additional documentation
└── requirements.txt           # Python dependencies
```

## 🔒 Security Architecture

### Encryption
- **Algorithm**: AES-256-GCM (Authenticated Encryption)
- **Key Derivation**: PBKDF2-HMAC-SHA256 (100,000 iterations)
- **Random IV**: Generated for each encryption operation
- **Authentication**: Built-in message authentication

### Storage
- **File Permissions**: Restrictive (0600 for files, 0700 for directories)
- **At-Rest Encryption**: All keys encrypted before storage
- **Memory Security**: Secure string handling, no plaintext in memory dumps

### Access Control
- **Master Key**: Required for all operations
- **Service Isolation**: Keys organized by service
- **Audit Trail**: Complete logging of all operations

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
python -m pytest tests/

# Run security tests only
python -m pytest tests/test_security.py

# Run with coverage
python -m pytest --cov=src tests/
```

### Test Coverage
- **Security Tests**: 13 tests covering encryption, access control, and vulnerabilities
- **Integration Tests**: 8 tests for full system workflows
- **Performance Tests**: 9 benchmarks for operation speed

## 📊 Performance

- **Write Performance**: ~5ms average
- **Read Performance**: ~2ms average
- **Concurrent Operations**: 100+ ops/second
- **Memory Usage**: ~5KB per key

## 🔧 Configuration

### Environment Variables
```bash
API_KEY_MASTER="your-master-key"        # Required: Master encryption key
API_KEY_STORAGE_DIR="~/.api_keys"       # Optional: Storage directory
API_KEY_LOG_LEVEL="INFO"                # Optional: Logging level
```

### Configuration File
Create `config.yaml`:
```yaml
storage:
  directory: ~/.api_keys
  backup_enabled: true
  
encryption:
  algorithm: AES-256-GCM
  iterations: 100000
  
rotation:
  auto_rotate: true
  days: 90
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) first.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 Security Best Practices

1. **Never commit your master key** - Use environment variables
2. **Rotate keys regularly** - Use the built-in rotation feature
3. **Backup your keys** - Use the export feature with encryption
4. **Use strong master keys** - Minimum 16 characters with mixed case and symbols
5. **Monitor access logs** - Review audit logs regularly

## 🐛 Known Issues

- Timing attack vulnerability (Low risk) - Being addressed in v2.0
- Windows clipboard integration requires additional setup
- Key names are visible in storage (encrypted values are secure)

## 🗺️ Roadmap

- [ ] Hardware Security Module (HSM) support
- [ ] Web UI with 2FA
- [ ] Cloud KMS integration (AWS, Azure, GCP)
- [ ] Docker container with volume encryption
- [ ] Kubernetes secrets integration
- [ ] Mobile app for key management

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built using best practices from OWASP and NIST guidelines
- Encryption powered by Python's `cryptography` library
- CLI interface built with `click`

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/murr2k/secure-api-key-storage/issues)
- **Discussions**: [GitHub Discussions](https://github.com/murr2k/secure-api-key-storage/discussions)
- **Security**: For security issues, please email security@example.com

---

<p align="center">Made with ❤️ by murr2k</p>