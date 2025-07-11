#!/bin/bash
# Example usage scenarios for Secure Key Manager

echo "=== Secure Key Manager - Example Usage ==="
echo ""

# Example 1: Basic Setup and Key Management
echo "1. Basic Setup and Key Management"
echo "---------------------------------"
cat << 'EOF'
# Initialize the key manager
./key-manager setup

# Add API keys for different services
./key-manager add github personal
./key-manager add openai api-key
./key-manager add aws access-key
./key-manager add aws secret-key

# List all configured services
./key-manager list

# Get a specific key (copies to clipboard)
./key-manager get github personal

# Show key value
./key-manager get github personal --show
EOF

echo ""
echo "2. Key Organization with Metadata"
echo "---------------------------------"
cat << 'EOF'
# Add keys with metadata for better organization
./key-manager add stripe prod-key --metadata '{"environment": "production", "created_by": "john"}'
./key-manager add stripe test-key --metadata '{"environment": "testing", "created_by": "john"}'

# Add GitHub tokens with different scopes
./key-manager add github read-only --metadata '{"scope": "repo:read", "expires": "2024-12-31"}'
./key-manager add github ci-cd --metadata '{"scope": "repo,workflow", "purpose": "GitHub Actions"}'
EOF

echo ""
echo "3. Key Rotation Workflow"
echo "-----------------------"
cat << 'EOF'
# Create backup before rotation
./key-manager backup --name "before-rotation"

# Rotate with auto-generated key
./key-manager rotate aws access-key

# Rotate with specific new value
./key-manager rotate github personal --new-value "ghp_newTokenValue123"

# Verify rotation
./key-manager list --service aws
EOF

echo ""
echo "4. Backup and Restore"
echo "--------------------"
cat << 'EOF'
# Create named backups
./key-manager backup --name "daily-backup"
./key-manager backup --name "before-deployment"

# List available backups
./key-manager restore list

# Restore from specific backup
./key-manager restore daily-backup
EOF

echo ""
echo "5. Environment-based Key Management"
echo "----------------------------------"
cat << 'EOF'
# Organize keys by environment
./key-manager add database-prod connection-string
./key-manager add database-staging connection-string  
./key-manager add database-dev connection-string

# Add AWS credentials for different accounts
./key-manager add aws-prod access-key
./key-manager add aws-prod secret-key
./key-manager add aws-staging access-key
./key-manager add aws-staging secret-key
EOF

echo ""
echo "6. CI/CD Integration"
echo "-------------------"
cat << 'EOF'
# Export keys for use in scripts
export GITHUB_TOKEN=$(./key-manager get github ci-cd --show)
export AWS_ACCESS_KEY=$(./key-manager get aws-prod access-key --show)
export AWS_SECRET_KEY=$(./key-manager get aws-prod secret-key --show)

# Use in deployment script
#!/bin/bash
GITHUB_TOKEN=$(./key-manager get github ci-cd --show)
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user
EOF

echo ""
echo "7. Team Workflow Example"
echo "-----------------------"
cat << 'EOF'
# Developer adds new service
./key-manager add slack webhook-url --metadata '{"channel": "#alerts", "added_by": "alice"}'

# Before major update, create backup
./key-manager backup --name "pre-update-$(date +%Y%m%d)"

# Rotate compromised key
./key-manager rotate slack webhook-url

# Verify and test
./key-manager get slack webhook-url --show
EOF

echo ""
echo "8. Automated Backup Script"
echo "-------------------------"
cat << 'EOF'
#!/bin/bash
# daily-backup.sh - Add to cron for daily backups

BACKUP_NAME="auto-backup-$(date +%Y%m%d-%H%M%S)"
./key-manager backup --name "$BACKUP_NAME"

# Keep only last 30 backups
cd ~/.secure-keys/backups
ls -t *.enc | tail -n +31 | xargs -r rm
EOF

echo ""
echo "9. Key Audit Script"
echo "------------------"
cat << 'EOF'
#!/bin/bash
# audit-keys.sh - List all keys with their last rotation date

echo "Key Audit Report - $(date)"
echo "========================="

# This would require extending the CLI to show rotation dates
./key-manager list

# For each service, check key age and suggest rotation
# (This is a conceptual example - would need CLI extension)
EOF

echo ""
echo "10. Disaster Recovery Plan"
echo "-------------------------"
cat << 'EOF'
# Regular backup schedule
0 2 * * * /path/to/key-manager backup --name "nightly-$(date +\%Y\%m\%d)"
0 2 * * 0 /path/to/key-manager backup --name "weekly-$(date +\%Y\%m\%d)"

# Store encrypted backup offsite
./key-manager backup --name "offsite-$(date +%Y%m%d)"
# Copy ~/.secure-keys/backups/offsite-*.enc to secure cloud storage

# Recovery procedure
1. Install key-manager on new system
2. Copy backup files to ~/.secure-keys/backups/
3. Run: ./key-manager restore <backup-name>
4. Verify: ./key-manager list
EOF