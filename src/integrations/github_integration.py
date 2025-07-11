"""
GitHub API Integration Module
Handles GitHub API authentication and key management
"""

import re
import requests
from typing import Dict, Optional, List
from base_integration import BaseIntegration


class GitHubIntegration(BaseIntegration):
    """GitHub API integration with secure key management"""
    
    def __init__(self, config_path: Optional[str] = None):
        super().__init__('GitHub', config_path)
        self.api_base_url = 'https://api.github.com'
        
    def validate_api_key(self, api_key: str) -> bool:
        """
        Validate GitHub API key format
        - Classic personal access tokens: 40 character hex string
        - Fine-grained personal access tokens: start with 'github_pat_'
        - OAuth tokens: typically 40 character hex string
        """
        # Classic token pattern
        classic_pattern = r'^[a-fA-F0-9]{40}$'
        # Fine-grained token pattern
        fine_grained_pattern = r'^github_pat_[a-zA-Z0-9_]+$'
        # OAuth token pattern (gho_ prefix)
        oauth_pattern = r'^gho_[a-zA-Z0-9]+$'
        
        return bool(
            re.match(classic_pattern, api_key) or
            re.match(fine_grained_pattern, api_key) or
            re.match(oauth_pattern, api_key)
        )
    
    def test_connection(self, api_key: str) -> bool:
        """Test GitHub API connection with the provided key"""
        try:
            headers = self._build_auth_headers(api_key)
            response = requests.get(f'{self.api_base_url}/user', headers=headers, timeout=10)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"GitHub connection test failed: {e}")
            return False
    
    def _build_auth_headers(self, api_key: str) -> Dict[str, str]:
        """Build GitHub authentication headers"""
        return {
            'Authorization': f'token {api_key}',
            'Accept': 'application/vnd.github.v3+json'
        }
    
    def get_user_info(self, api_key: Optional[str] = None) -> Optional[Dict]:
        """Get authenticated user information"""
        try:
            headers = self.get_headers(api_key)
            response = requests.get(f'{self.api_base_url}/user', headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            self.logger.error(f"Failed to get GitHub user info: {e}")
            return None
    
    def get_rate_limit(self, api_key: Optional[str] = None) -> Optional[Dict]:
        """Get current API rate limit status"""
        try:
            headers = self.get_headers(api_key)
            response = requests.get(f'{self.api_base_url}/rate_limit', headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            self.logger.error(f"Failed to get GitHub rate limit: {e}")
            return None
    
    def list_repos(self, api_key: Optional[str] = None, user: Optional[str] = None) -> Optional[List[Dict]]:
        """List repositories for authenticated user or specified user"""
        try:
            headers = self.get_headers(api_key)
            if user:
                url = f'{self.api_base_url}/users/{user}/repos'
            else:
                url = f'{self.api_base_url}/user/repos'
            
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            self.logger.error(f"Failed to list GitHub repos: {e}")
            return None
    
    def create_repo(self, name: str, description: str = "", private: bool = False,
                   api_key: Optional[str] = None) -> Optional[Dict]:
        """Create a new repository"""
        try:
            headers = self.get_headers(api_key)
            data = {
                'name': name,
                'description': description,
                'private': private
            }
            response = requests.post(
                f'{self.api_base_url}/user/repos',
                headers=headers,
                json=data,
                timeout=10
            )
            if response.status_code == 201:
                return response.json()
            return None
        except Exception as e:
            self.logger.error(f"Failed to create GitHub repo: {e}")
            return None
    
    def get_repo(self, owner: str, repo: str, api_key: Optional[str] = None) -> Optional[Dict]:
        """Get repository information"""
        try:
            headers = self.get_headers(api_key)
            response = requests.get(
                f'{self.api_base_url}/repos/{owner}/{repo}',
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            self.logger.error(f"Failed to get GitHub repo: {e}")
            return None
    
    def configure_scopes(self, required_scopes: List[str]) -> None:
        """Configure required GitHub token scopes"""
        self._config['required_scopes'] = required_scopes
        self.save_config(self._config)
    
    def check_token_scopes(self, api_key: Optional[str] = None) -> Optional[List[str]]:
        """Check the scopes of the current token"""
        try:
            headers = self.get_headers(api_key)
            response = requests.head(f'{self.api_base_url}/user', headers=headers, timeout=10)
            if response.status_code == 200:
                scope_header = response.headers.get('X-OAuth-Scopes', '')
                return [s.strip() for s in scope_header.split(',')] if scope_header else []
            return None
        except Exception as e:
            self.logger.error(f"Failed to check GitHub token scopes: {e}")
            return None


# Example usage functions
def create_github_integration() -> GitHubIntegration:
    """Create and configure GitHub integration"""
    github = GitHubIntegration()
    
    # Configure required scopes
    github.configure_scopes([
        'repo',        # Full control of private repositories
        'user',        # Read user profile data
        'workflow',    # Update GitHub Action workflows
        'admin:org'    # Read org data
    ])
    
    return github


def github_wrapper_example():
    """Example of using GitHub integration with wrapper functions"""
    from base_integration import SecureKeyWrapper
    
    # Create wrapper and register GitHub integration
    wrapper = SecureKeyWrapper()
    github = create_github_integration()
    wrapper.register_integration(github)
    
    # Set API key
    api_key = "your_github_token_here"
    if wrapper.set_key('github', api_key):
        print("GitHub API key stored successfully")
    
    # Use the integration
    user_info = github.get_user_info()
    if user_info:
        print(f"Authenticated as: {user_info.get('login')}")
    
    # Get rate limit
    rate_limit = github.get_rate_limit()
    if rate_limit:
        print(f"API calls remaining: {rate_limit.get('rate', {}).get('remaining')}")
    
    return wrapper