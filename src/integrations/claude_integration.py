"""
Claude API Integration Module
Handles Claude/Anthropic API authentication and key management
"""

import re
import requests
from typing import Dict, Optional, List, Any
from base_integration import BaseIntegration


class ClaudeIntegration(BaseIntegration):
    """Claude/Anthropic API integration with secure key management"""
    
    def __init__(self, config_path: Optional[str] = None):
        super().__init__('Claude', config_path)
        self.api_base_url = 'https://api.anthropic.com/v1'
        self.api_version = '2023-06-01'
        
    def validate_api_key(self, api_key: str) -> bool:
        """
        Validate Claude/Anthropic API key format
        - Should start with 'sk-ant-'
        - Followed by alphanumeric characters and hyphens
        """
        pattern = r'^sk-ant-[a-zA-Z0-9\-]+$'
        return bool(re.match(pattern, api_key))
    
    def test_connection(self, api_key: str) -> bool:
        """Test Claude API connection with the provided key"""
        try:
            headers = self._build_auth_headers(api_key)
            # Test with a minimal completion request
            response = requests.post(
                f'{self.api_base_url}/messages',
                headers=headers,
                json={
                    'model': 'claude-3-haiku-20240307',
                    'messages': [{'role': 'user', 'content': 'test'}],
                    'max_tokens': 1
                },
                timeout=10
            )
            # Check if we get a valid response or authentication error
            return response.status_code in [200, 429]  # 429 is rate limit, still valid auth
        except Exception as e:
            self.logger.error(f"Claude connection test failed: {e}")
            return False
    
    def _build_auth_headers(self, api_key: str) -> Dict[str, str]:
        """Build Claude authentication headers"""
        return {
            'x-api-key': api_key,
            'anthropic-version': self.api_version,
            'content-type': 'application/json'
        }
    
    def create_message(self, messages: List[Dict[str, str]], model: str = 'claude-3-sonnet-20240229',
                      max_tokens: int = 1000, temperature: float = 0.0,
                      api_key: Optional[str] = None, **kwargs) -> Optional[Dict]:
        """Create a message with Claude"""
        try:
            headers = self.get_headers(api_key)
            data = {
                'model': model,
                'messages': messages,
                'max_tokens': max_tokens,
                'temperature': temperature,
                **kwargs
            }
            
            response = requests.post(
                f'{self.api_base_url}/messages',
                headers=headers,
                json=data,
                timeout=60
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"Claude API error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            self.logger.error(f"Failed to create Claude message: {e}")
            return None
    
    def stream_message(self, messages: List[Dict[str, str]], model: str = 'claude-3-sonnet-20240229',
                      max_tokens: int = 1000, temperature: float = 0.0,
                      api_key: Optional[str] = None, **kwargs):
        """Stream a message response from Claude"""
        try:
            headers = self.get_headers(api_key)
            data = {
                'model': model,
                'messages': messages,
                'max_tokens': max_tokens,
                'temperature': temperature,
                'stream': True,
                **kwargs
            }
            
            response = requests.post(
                f'{self.api_base_url}/messages',
                headers=headers,
                json=data,
                stream=True,
                timeout=60
            )
            
            if response.status_code == 200:
                for line in response.iter_lines():
                    if line:
                        yield line.decode('utf-8')
            else:
                self.logger.error(f"Claude API stream error: {response.status_code}")
                yield None
        except Exception as e:
            self.logger.error(f"Failed to stream Claude message: {e}")
            yield None
    
    def count_tokens(self, text: str, api_key: Optional[str] = None) -> Optional[int]:
        """Count tokens in text (approximation for Claude)"""
        # Claude doesn't provide a token counting endpoint, so we approximate
        # Rough estimate: 1 token ≈ 4 characters
        return len(text) // 4
    
    def configure_model_preferences(self, models: List[str]) -> None:
        """Configure preferred Claude models"""
        self._config['preferred_models'] = models
        self.save_config(self._config)
    
    def get_available_models(self) -> List[str]:
        """Get list of available Claude models"""
        return [
            'claude-3-opus-20240229',
            'claude-3-sonnet-20240229',
            'claude-3-haiku-20240307',
            'claude-2.1',
            'claude-2.0',
            'claude-instant-1.2'
        ]
    
    def create_prompt_template(self, name: str, template: str, variables: List[str]) -> None:
        """Create a reusable prompt template"""
        if 'prompt_templates' not in self._config:
            self._config['prompt_templates'] = {}
        
        self._config['prompt_templates'][name] = {
            'template': template,
            'variables': variables
        }
        self.save_config(self._config)
    
    def use_prompt_template(self, name: str, **variables) -> Optional[str]:
        """Use a saved prompt template"""
        templates = self._config.get('prompt_templates', {})
        if name not in templates:
            self.logger.error(f"Prompt template '{name}' not found")
            return None
        
        template = templates[name]['template']
        try:
            return template.format(**variables)
        except KeyError as e:
            self.logger.error(f"Missing variable in template: {e}")
            return None
    
    def configure_safety_settings(self, settings: Dict[str, Any]) -> None:
        """Configure safety and moderation settings"""
        self._config['safety_settings'] = settings
        self.save_config(self._config)
    
    def get_usage_stats(self) -> Dict[str, Any]:
        """Get usage statistics (placeholder - would need implementation)"""
        return {
            'total_requests': self._config.get('usage_stats', {}).get('total_requests', 0),
            'total_tokens': self._config.get('usage_stats', {}).get('total_tokens', 0),
            'models_used': self._config.get('usage_stats', {}).get('models_used', {})
        }


# Example usage functions
def create_claude_integration() -> ClaudeIntegration:
    """Create and configure Claude integration"""
    claude = ClaudeIntegration()
    
    # Configure preferred models
    claude.configure_model_preferences([
        'claude-3-sonnet-20240229',  # Default model
        'claude-3-opus-20240229',     # For complex tasks
        'claude-3-haiku-20240307'     # For simple/fast tasks
    ])
    
    # Create prompt templates
    claude.create_prompt_template(
        'code_review',
        'Please review the following {language} code and provide feedback on:\n'
        '1. Code quality\n2. Potential bugs\n3. Performance improvements\n\n'
        'Code:\n```{language}\n{code}\n```',
        ['language', 'code']
    )
    
    claude.create_prompt_template(
        'explain_code',
        'Please explain the following {language} code in simple terms:\n\n'
        '```{language}\n{code}\n```',
        ['language', 'code']
    )
    
    # Configure safety settings
    claude.configure_safety_settings({
        'allow_flagged_content': False,
        'block_harmful_content': True,
        'content_filtering_level': 'moderate'
    })
    
    return claude


def claude_wrapper_example():
    """Example of using Claude integration with wrapper functions"""
    from base_integration import SecureKeyWrapper
    
    # Create wrapper and register Claude integration
    wrapper = SecureKeyWrapper()
    claude = create_claude_integration()
    wrapper.register_integration(claude)
    
    # Set API key
    api_key = "sk-ant-your-api-key-here"
    if wrapper.set_key('claude', api_key):
        print("Claude API key stored successfully")
    
    # Use the integration
    response = claude.create_message(
        messages=[{'role': 'user', 'content': 'Hello, Claude!'}],
        model='claude-3-haiku-20240307',
        max_tokens=100
    )
    
    if response:
        print(f"Claude response: {response.get('content', [{}])[0].get('text', '')}")
    
    # Use a prompt template
    code_explanation = claude.use_prompt_template(
        'explain_code',
        language='python',
        code='def fibonacci(n):\n    return n if n <= 1 else fibonacci(n-1) + fibonacci(n-2)'
    )
    
    if code_explanation:
        response = claude.create_message(
            messages=[{'role': 'user', 'content': code_explanation}],
            model='claude-3-sonnet-20240229',
            max_tokens=500
        )
    
    return wrapper