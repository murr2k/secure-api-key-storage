"""
Generic Service Integration Module
Provides flexible integration for any API service
"""

import re
import requests
from typing import Dict, Optional, Any, Callable
from base_integration import BaseIntegration


class GenericServiceIntegration(BaseIntegration):
    """Generic API integration for custom services"""
    
    def __init__(self, service_name: str, config_path: Optional[str] = None):
        super().__init__(service_name, config_path)
        self._validation_pattern = None
        self._test_endpoint = None
        self._auth_type = 'header'  # header, query, basic
        self._auth_field = 'Authorization'
        self._auth_prefix = 'Bearer'
        
    def configure_validation(self, pattern: str) -> None:
        """Configure API key validation pattern"""
        self._validation_pattern = pattern
        self._config['validation_pattern'] = pattern
        self.save_config(self._config)
    
    def configure_test_endpoint(self, endpoint: str, expected_status: int = 200) -> None:
        """Configure endpoint for connection testing"""
        self._test_endpoint = endpoint
        self._config['test_endpoint'] = endpoint
        self._config['expected_status'] = expected_status
        self.save_config(self._config)
    
    def configure_auth_method(self, auth_type: str, auth_field: str, auth_prefix: str = '') -> None:
        """
        Configure authentication method
        
        Args:
            auth_type: 'header', 'query', or 'basic'
            auth_field: Field name for authentication (e.g., 'Authorization', 'api_key')
            auth_prefix: Prefix for auth value (e.g., 'Bearer', 'Token')
        """
        self._auth_type = auth_type
        self._auth_field = auth_field
        self._auth_prefix = auth_prefix
        
        self._config['auth_type'] = auth_type
        self._config['auth_field'] = auth_field
        self._config['auth_prefix'] = auth_prefix
        self.save_config(self._config)
    
    def validate_api_key(self, api_key: str) -> bool:
        """Validate API key using configured pattern"""
        if not self._validation_pattern:
            # If no pattern configured, accept any non-empty string
            return bool(api_key and api_key.strip())
        
        return bool(re.match(self._validation_pattern, api_key))
    
    def test_connection(self, api_key: str) -> bool:
        """Test API connection using configured endpoint"""
        if not self._test_endpoint:
            # If no test endpoint configured, assume valid
            self.logger.warning(f"No test endpoint configured for {self.service_name}")
            return True
        
        try:
            headers = self._build_auth_headers(api_key)
            params = {}
            
            if self._auth_type == 'query':
                params[self._auth_field] = api_key
                headers = {}
            
            response = requests.get(
                self._test_endpoint,
                headers=headers,
                params=params,
                timeout=10
            )
            
            expected_status = self._config.get('expected_status', 200)
            return response.status_code == expected_status
        except Exception as e:
            self.logger.error(f"{self.service_name} connection test failed: {e}")
            return False
    
    def _build_auth_headers(self, api_key: str) -> Dict[str, str]:
        """Build authentication headers based on configuration"""
        if self._auth_type == 'header':
            value = f"{self._auth_prefix} {api_key}".strip() if self._auth_prefix else api_key
            return {self._auth_field: value}
        elif self._auth_type == 'basic':
            import base64
            encoded = base64.b64encode(f"{api_key}:".encode()).decode()
            return {'Authorization': f'Basic {encoded}'}
        else:
            # For query auth, headers are empty
            return {}
    
    def make_request(self, method: str, url: str, api_key: Optional[str] = None,
                    headers: Optional[Dict] = None, **kwargs) -> Optional[requests.Response]:
        """Make authenticated request to the service"""
        try:
            auth_headers = self.get_headers(api_key)
            if headers:
                auth_headers.update(headers)
            
            # Handle query parameter authentication
            if self._auth_type == 'query':
                if 'params' not in kwargs:
                    kwargs['params'] = {}
                kwargs['params'][self._auth_field] = api_key or self.get_secure_key()
                auth_headers = headers or {}
            
            response = requests.request(
                method=method,
                url=url,
                headers=auth_headers,
                timeout=kwargs.pop('timeout', 30),
                **kwargs
            )
            
            return response
        except Exception as e:
            self.logger.error(f"Request failed for {self.service_name}: {e}")
            return None
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make GET request"""
        return self.make_request('GET', url, **kwargs)
    
    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make POST request"""
        return self.make_request('POST', url, **kwargs)
    
    def put(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make PUT request"""
        return self.make_request('PUT', url, **kwargs)
    
    def delete(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make DELETE request"""
        return self.make_request('DELETE', url, **kwargs)
    
    def patch(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make PATCH request"""
        return self.make_request('PATCH', url, **kwargs)


# Pre-configured integrations for common services
def create_openai_integration() -> GenericServiceIntegration:
    """Create OpenAI API integration"""
    openai = GenericServiceIntegration('OpenAI')
    openai.configure_validation(r'^sk-[a-zA-Z0-9]{48}$')
    openai.configure_test_endpoint('https://api.openai.com/v1/models')
    openai.configure_auth_method('header', 'Authorization', 'Bearer')
    return openai


def create_slack_integration() -> GenericServiceIntegration:
    """Create Slack API integration"""
    slack = GenericServiceIntegration('Slack')
    slack.configure_validation(r'^xoxb-[0-9]{11,}-[0-9]{11,}-[a-zA-Z0-9]{24,}$')
    slack.configure_test_endpoint('https://slack.com/api/auth.test')
    slack.configure_auth_method('header', 'Authorization', 'Bearer')
    return slack


def create_stripe_integration() -> GenericServiceIntegration:
    """Create Stripe API integration"""
    stripe = GenericServiceIntegration('Stripe')
    stripe.configure_validation(r'^sk_(test_|live_)[a-zA-Z0-9]{24,}$')
    stripe.configure_test_endpoint('https://api.stripe.com/v1/charges', expected_status=401)
    stripe.configure_auth_method('basic', 'Authorization')
    return stripe


def create_sendgrid_integration() -> GenericServiceIntegration:
    """Create SendGrid API integration"""
    sendgrid = GenericServiceIntegration('SendGrid')
    sendgrid.configure_validation(r'^SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}$')
    sendgrid.configure_test_endpoint('https://api.sendgrid.com/v3/scopes')
    sendgrid.configure_auth_method('header', 'Authorization', 'Bearer')
    return sendgrid


def create_custom_integration(
    service_name: str,
    base_url: str,
    auth_type: str = 'header',
    auth_field: str = 'Authorization',
    auth_prefix: str = 'Bearer',
    validation_pattern: Optional[str] = None,
    test_path: str = '/'
) -> GenericServiceIntegration:
    """
    Create a custom service integration
    
    Args:
        service_name: Name of the service
        base_url: Base URL of the API
        auth_type: Authentication type ('header', 'query', 'basic')
        auth_field: Field name for authentication
        auth_prefix: Prefix for auth value
        validation_pattern: Regex pattern for key validation
        test_path: Path to test endpoint
    """
    integration = GenericServiceIntegration(service_name)
    
    if validation_pattern:
        integration.configure_validation(validation_pattern)
    
    integration.configure_test_endpoint(f"{base_url.rstrip('/')}/{test_path.lstrip('/')}")
    integration.configure_auth_method(auth_type, auth_field, auth_prefix)
    
    # Store base URL in config
    integration._config['base_url'] = base_url
    integration.save_config(integration._config)
    
    return integration


# Example usage
def generic_integration_example():
    """Example of using generic integrations"""
    from base_integration import SecureKeyWrapper
    
    # Create wrapper
    wrapper = SecureKeyWrapper()
    
    # Register pre-configured services
    wrapper.register_integration(create_openai_integration())
    wrapper.register_integration(create_slack_integration())
    wrapper.register_integration(create_stripe_integration())
    
    # Create and register custom service
    custom_api = create_custom_integration(
        service_name='MyCustomAPI',
        base_url='https://api.myservice.com',
        auth_type='header',
        auth_field='X-API-Key',
        auth_prefix='',  # No prefix
        validation_pattern=r'^[A-Z0-9]{32}$',
        test_path='/v1/status'
    )
    wrapper.register_integration(custom_api)
    
    # Use the custom service
    if wrapper.set_key('MyCustomAPI', 'YOUR32CHARACTERAPIKEY12345678901'):
        response = custom_api.get('https://api.myservice.com/v1/data')
        if response and response.status_code == 200:
            print(f"Data retrieved: {response.json()}")
    
    return wrapper