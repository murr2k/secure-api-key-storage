#!/usr/bin/env python3
"""
Integration examples for using Secure Key Manager with various services and frameworks.
"""

import subprocess
import os
import json
from typing import Optional


class KeyManagerClient:
    """Python client for interacting with the Secure Key Manager CLI."""
    
    def __init__(self, cli_path: str = "./key-manager", master_password: Optional[str] = None):
        self.cli_path = cli_path
        self.master_password = master_password or os.environ.get('KEY_MANAGER_PASSWORD')
    
    def get_key(self, service: str, key_name: str) -> Optional[str]:
        """Retrieve a key from the key manager."""
        try:
            cmd = [self.cli_path, 'get', service, key_name, '--show']
            result = subprocess.run(
                cmd,
                input=f"{self.master_password}\n",
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                # Extract the key value from output
                lines = result.stdout.strip().split('\n')
                # The last line should contain the key
                return lines[-1].strip()
            return None
        except Exception as e:
            print(f"Error retrieving key: {e}")
            return None


# Example 1: GitHub API Integration
def github_integration_example():
    """Example of using key manager with GitHub API."""
    print("=== GitHub API Integration ===")
    
    km = KeyManagerClient()
    github_token = km.get_key('github', 'personal')
    
    if github_token:
        import requests
        
        headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        # Get user info
        response = requests.get('https://api.github.com/user', headers=headers)
        user_data = response.json()
        print(f"Authenticated as: {user_data.get('login', 'Unknown')}")
        
        # List repositories
        repos_response = requests.get('https://api.github.com/user/repos', headers=headers)
        repos = repos_response.json()
        print(f"Found {len(repos)} repositories")


# Example 2: AWS SDK Integration
def aws_integration_example():
    """Example of using key manager with AWS SDK (boto3)."""
    print("\n=== AWS SDK Integration ===")
    
    km = KeyManagerClient()
    access_key = km.get_key('aws-prod', 'access-key')
    secret_key = km.get_key('aws-prod', 'secret-key')
    
    if access_key and secret_key:
        try:
            import boto3
            
            # Create AWS session with credentials from key manager
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='us-east-1'
            )
            
            # Example: List S3 buckets
            s3 = session.client('s3')
            response = s3.list_buckets()
            
            print(f"Found {len(response['Buckets'])} S3 buckets")
            for bucket in response['Buckets']:
                print(f"  - {bucket['Name']}")
        except ImportError:
            print("boto3 not installed. Run: pip install boto3")


# Example 3: OpenAI Integration
def openai_integration_example():
    """Example of using key manager with OpenAI API."""
    print("\n=== OpenAI Integration ===")
    
    km = KeyManagerClient()
    openai_key = km.get_key('openai', 'api-key')
    
    if openai_key:
        try:
            import openai
            
            openai.api_key = openai_key
            
            # Example: List available models
            models = openai.Model.list()
            print(f"Available models: {len(models['data'])}")
            
            # Example: Simple completion
            response = openai.Completion.create(
                model="text-davinci-003",
                prompt="Hello, AI!",
                max_tokens=50
            )
            print(f"AI Response: {response.choices[0].text.strip()}")
        except ImportError:
            print("openai not installed. Run: pip install openai")


# Example 4: Database Connection
def database_integration_example():
    """Example of using key manager for database connections."""
    print("\n=== Database Integration ===")
    
    km = KeyManagerClient()
    db_connection_string = km.get_key('database-prod', 'connection-string')
    
    if db_connection_string:
        # Example with PostgreSQL
        try:
            import psycopg2
            
            conn = psycopg2.connect(db_connection_string)
            cursor = conn.cursor()
            
            cursor.execute("SELECT version();")
            db_version = cursor.fetchone()
            print(f"Connected to: {db_version[0]}")
            
            cursor.close()
            conn.close()
        except ImportError:
            print("psycopg2 not installed. Run: pip install psycopg2-binary")
        except Exception as e:
            print(f"Database connection error: {e}")


# Example 5: Environment Variables Setup
def setup_environment_variables():
    """Example of setting up environment variables from key manager."""
    print("\n=== Environment Variables Setup ===")
    
    km = KeyManagerClient()
    
    # Define the keys to export
    env_keys = [
        ('GITHUB_TOKEN', 'github', 'personal'),
        ('AWS_ACCESS_KEY_ID', 'aws-prod', 'access-key'),
        ('AWS_SECRET_ACCESS_KEY', 'aws-prod', 'secret-key'),
        ('OPENAI_API_KEY', 'openai', 'api-key'),
        ('DATABASE_URL', 'database-prod', 'connection-string'),
    ]
    
    # Export to current process
    for env_var, service, key_name in env_keys:
        value = km.get_key(service, key_name)
        if value:
            os.environ[env_var] = value
            print(f"✓ Set {env_var}")
        else:
            print(f"✗ Failed to set {env_var}")
    
    # Generate .env file
    with open('.env', 'w') as f:
        for env_var, service, key_name in env_keys:
            value = km.get_key(service, key_name)
            if value:
                f.write(f"{env_var}={value}\n")
    
    print("\n✓ Generated .env file")


# Example 6: Docker Integration
def docker_integration_example():
    """Example of using key manager with Docker."""
    print("\n=== Docker Integration ===")
    
    # Generate docker-compose with secrets
    docker_compose_template = """version: '3.8'

services:
  app:
    image: myapp:latest
    environment:
      - GITHUB_TOKEN={github_token}
      - AWS_ACCESS_KEY_ID={aws_access_key}
      - AWS_SECRET_ACCESS_KEY={aws_secret_key}
      - DATABASE_URL={database_url}
    secrets:
      - api_keys

secrets:
  api_keys:
    file: ./secrets/api_keys.json
"""
    
    km = KeyManagerClient()
    
    # Get keys
    config = {
        'github_token': km.get_key('github', 'ci-cd'),
        'aws_access_key': km.get_key('aws-prod', 'access-key'),
        'aws_secret_key': km.get_key('aws-prod', 'secret-key'),
        'database_url': km.get_key('database-prod', 'connection-string'),
    }
    
    # Generate docker-compose.yml
    docker_compose = docker_compose_template.format(**config)
    
    with open('docker-compose.yml', 'w') as f:
        f.write(docker_compose)
    
    print("✓ Generated docker-compose.yml with secrets")
    
    # Create secrets file
    os.makedirs('secrets', exist_ok=True)
    secrets_data = {
        'github': config['github_token'],
        'aws': {
            'access_key': config['aws_access_key'],
            'secret_key': config['aws_secret_key']
        },
        'database': config['database_url']
    }
    
    with open('secrets/api_keys.json', 'w') as f:
        json.dump(secrets_data, f, indent=2)
    
    print("✓ Created secrets/api_keys.json")


# Example 7: CI/CD Pipeline Integration
def cicd_integration_example():
    """Example of using key manager in CI/CD pipelines."""
    print("\n=== CI/CD Pipeline Integration ===")
    
    # GitHub Actions example
    github_actions_yml = """name: Deploy

on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Setup Key Manager
      run: |
        # Install key manager
        pip install click rich cryptography
        chmod +x key-manager-cli.py
        
    - name: Configure AWS credentials
      run: |
        # Use key manager to get credentials
        export AWS_ACCESS_KEY_ID=$(./key-manager get aws-prod access-key --show)
        export AWS_SECRET_ACCESS_KEY=$(./key-manager get aws-prod secret-key --show)
        
        # Configure AWS CLI
        aws configure set aws_access_key_id $AWS_ACCESS_KEY_ID
        aws configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY
        aws configure set default.region us-east-1
        
    - name: Deploy to AWS
      run: |
        # Your deployment commands here
        aws s3 sync ./dist s3://my-bucket
"""
    
    with open('.github/workflows/deploy.yml', 'w') as f:
        f.write(github_actions_yml)
    
    print("✓ Generated .github/workflows/deploy.yml")
    
    # GitLab CI example
    gitlab_ci_yml = """.deploy:
  stage: deploy
  script:
    - pip install click rich cryptography
    - chmod +x key-manager-cli.py
    - export AWS_ACCESS_KEY_ID=$(./key-manager get aws-prod access-key --show)
    - export AWS_SECRET_ACCESS_KEY=$(./key-manager get aws-prod secret-key --show)
    - aws s3 sync ./dist s3://my-bucket
  only:
    - main
"""
    
    with open('.gitlab-ci.yml', 'w') as f:
        f.write(gitlab_ci_yml)
    
    print("✓ Generated .gitlab-ci.yml")


# Example 8: Kubernetes Secrets Integration
def kubernetes_integration_example():
    """Example of using key manager with Kubernetes secrets."""
    print("\n=== Kubernetes Integration ===")
    
    km = KeyManagerClient()
    
    # Get keys for Kubernetes secret
    secrets = {
        'github-token': km.get_key('github', 'ci-cd'),
        'aws-access-key': km.get_key('aws-prod', 'access-key'),
        'aws-secret-key': km.get_key('aws-prod', 'secret-key'),
        'database-url': km.get_key('database-prod', 'connection-string'),
    }
    
    # Generate Kubernetes secret YAML
    k8s_secret = f"""apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: production
type: Opaque
data:"""
    
    import base64
    
    for key, value in secrets.items():
        if value:
            encoded_value = base64.b64encode(value.encode()).decode()
            k8s_secret += f"\n  {key}: {encoded_value}"
    
    with open('k8s-secrets.yaml', 'w') as f:
        f.write(k8s_secret)
    
    print("✓ Generated k8s-secrets.yaml")
    
    # Generate deployment using the secret
    k8s_deployment = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: app
        image: myapp:latest
        env:
        - name: GITHUB_TOKEN
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: github-token
        - name: AWS_ACCESS_KEY_ID
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: aws-access-key
        - name: AWS_SECRET_ACCESS_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: aws-secret-key
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: database-url
"""
    
    with open('k8s-deployment.yaml', 'w') as f:
        f.write(k8s_deployment)
    
    print("✓ Generated k8s-deployment.yaml")


# Main execution
if __name__ == "__main__":
    print("Secure Key Manager - Integration Examples")
    print("=========================================")
    print("\nNote: Set KEY_MANAGER_PASSWORD environment variable or")
    print("modify the examples to provide the master password.\n")
    
    # Uncomment the examples you want to run:
    
    # github_integration_example()
    # aws_integration_example()
    # openai_integration_example()
    # database_integration_example()
    # setup_environment_variables()
    # docker_integration_example()
    # cicd_integration_example()
    # kubernetes_integration_example()
    
    print("\nTo run specific examples, uncomment them in the main section.")
    print("Make sure to install required dependencies for each integration.")