#!/usr/bin/env python3
"""
AI-powered API Description Generator with Caching
"""

import os
import json
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import openai
from app.config import Config

logger = logging.getLogger(__name__)

class AIDescriptionGenerator:
    """AI-powered API description generator with caching"""
    
    def __init__(self):
        openai.api_key = Config.OPENAI_API_KEY
        self.cache_file = os.path.join(Config.DATA_DIR, 'ai_cache.json')
        self.cache_ttl = timedelta(hours=24)  # Cache for 24 hours
        self._load_cache()
    
    def _load_cache(self):
        """Load cache from file"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
                logger.info(f"✅ Loaded AI cache with {len(self.cache)} entries")
            else:
                self.cache = {}
                logger.info("ℹ️  No AI cache found, starting fresh")
        except Exception as e:
            logger.error(f"❌ Error loading AI cache: {e}")
            self.cache = {}
    
    def _save_cache(self):
        """Save cache to file"""
        try:
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2, default=str)
            logger.debug(f"💾 Saved AI cache with {len(self.cache)} entries")
        except Exception as e:
            logger.error(f"❌ Error saving AI cache: {e}")
    
    def _generate_cache_key(self, endpoint_data: Dict[str, Any]) -> str:
        """Generate a unique cache key for endpoint data"""
        # Create a hash of the endpoint data that affects the description
        key_data = {
            'method': endpoint_data.get('method', ''),
            'path': endpoint_data.get('path', ''),
            'summary': endpoint_data.get('summary', ''),
            'description': endpoint_data.get('description', ''),
            'parameters_schema': endpoint_data.get('parameters_schema', {}),
            'request_body_schema': endpoint_data.get('request_body_schema', {})
        }
        
        # Convert to sorted JSON string for consistent hashing
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _is_cache_valid(self, cache_entry: Dict[str, Any]) -> bool:
        """Check if cache entry is still valid"""
        try:
            cached_time = datetime.fromisoformat(cache_entry['timestamp'])
            return datetime.now() - cached_time < self.cache_ttl
        except Exception:
            return False
    
    def generate_endpoint_description(self, endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI description for an endpoint with caching"""
        try:
            # Generate cache key
            cache_key = self._generate_cache_key(endpoint_data)
            
            # Check cache first
            if cache_key in self.cache and self._is_cache_valid(self.cache[cache_key]):
                logger.info(f"✅ Using cached AI description for {endpoint_data.get('path', 'Unknown')}")
                return self.cache[cache_key]['result']
            
            # Generate new description
            logger.info(f"🤖 Generating new AI description for {endpoint_data.get('path', 'Unknown')}")
            result = self._generate_description_with_ai(endpoint_data)
            
            # Cache the result
            self.cache[cache_key] = {
                'timestamp': datetime.now().isoformat(),
                'result': result
            }
            self._save_cache()
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Error generating AI description: {e}")
            return {
                'description': f"Error generating description: {str(e)}",
                'security_analysis': "Unable to analyze security due to generation error.",
                'risk_assessment': "Risk assessment unavailable due to generation error.",
                'recommendations': ["Fix the underlying error to generate recommendations."]
            }
    
    def _generate_description_with_ai(self, endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate description using OpenAI API"""
        try:
            # Prepare the prompt
            prompt = self._build_prompt(endpoint_data)
            
            # Call OpenAI API
            client = openai.OpenAI(api_key=Config.OPENAI_API_KEY)
            response = client.chat.completions.create(
                model=Config.OPENAI_MODEL,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert API security analyst and documentation specialist. Provide detailed, accurate, and security-focused descriptions of API endpoints."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=2000,
                temperature=0.3  # Lower temperature for more consistent results
            )
            
            # Parse the response
            content = response.choices[0].message.content
            
            # Extract sections from the response
            sections = self._parse_ai_response(content)
            
            return {
                'description': sections.get('description', 'No description generated.'),
                'security_analysis': sections.get('security_analysis', 'No security analysis available.'),
                'risk_assessment': sections.get('risk_assessment', 'No risk assessment available.'),
                'recommendations': sections.get('recommendations', ['No recommendations available.'])
            }
            
        except Exception as e:
            logger.error(f"❌ OpenAI API error: {e}")
            raise
    
    def _build_prompt(self, endpoint_data: Dict[str, Any]) -> str:
        """Build the prompt for AI generation"""
        method = endpoint_data.get('method', 'GET')
        path = endpoint_data.get('path', '/')
        summary = endpoint_data.get('summary', 'No summary available')
        description = endpoint_data.get('description', 'No description available')
        parameters = endpoint_data.get('parameters_schema', {})
        request_body = endpoint_data.get('request_body_schema', {})
        
        prompt = f"""
Please analyze this API endpoint and provide a comprehensive description with security insights:

**Endpoint Details:**
- Method: {method}
- Path: {path}
- Summary: {summary}
- Description: {description}

**Parameters Schema:**
{json.dumps(parameters, indent=2) if parameters else 'No parameters defined'}

**Request Body Schema:**
{json.dumps(request_body, indent=2) if request_body else 'No request body defined'}

Please provide your response in the following format:

**DESCRIPTION:**
[Provide a detailed, user-friendly description of what this endpoint does, its purpose, and how it should be used]

**SECURITY_ANALYSIS:**
[Analyze potential security risks, vulnerabilities, and security considerations for this endpoint]

**RISK_ASSESSMENT:**
[Provide a risk assessment including risk level (low/medium/high/critical), risk score (1-10), and key risk factors]

**RECOMMENDATIONS:**
[Provide specific security recommendations and best practices for using this endpoint securely]

Please ensure your response is comprehensive, accurate, and focused on security best practices.
"""
        return prompt
    
    def _parse_ai_response(self, content: str) -> Dict[str, Any]:
        """Parse the AI response into sections"""
        sections = {}
        
        # Extract description
        if '**DESCRIPTION:**' in content:
            desc_start = content.find('**DESCRIPTION:**') + len('**DESCRIPTION:**')
            desc_end = content.find('**SECURITY_ANALYSIS:**') if '**SECURITY_ANALYSIS:**' in content else len(content)
            sections['description'] = content[desc_start:desc_end].strip()
        
        # Extract security analysis
        if '**SECURITY_ANALYSIS:**' in content:
            sec_start = content.find('**SECURITY_ANALYSIS:**') + len('**SECURITY_ANALYSIS:**')
            sec_end = content.find('**RISK_ASSESSMENT:**') if '**RISK_ASSESSMENT:**' in content else len(content)
            sections['security_analysis'] = content[sec_start:sec_end].strip()
        
        # Extract risk assessment
        if '**RISK_ASSESSMENT:**' in content:
            risk_start = content.find('**RISK_ASSESSMENT:**') + len('**RISK_ASSESSMENT:**')
            risk_end = content.find('**RECOMMENDATIONS:**') if '**RECOMMENDATIONS:**' in content else len(content)
            sections['risk_assessment'] = content[risk_start:risk_end].strip()
        
        # Extract recommendations
        if '**RECOMMENDATIONS:**' in content:
            rec_start = content.find('**RECOMMENDATIONS:**') + len('**RECOMMENDATIONS:**')
            recommendations_text = content[rec_start:].strip()
            # Split recommendations into list
            recommendations = [rec.strip() for rec in recommendations_text.split('\n') if rec.strip()]
            sections['recommendations'] = recommendations
        
        return sections
    
    def clear_cache(self) -> bool:
        """Clear the AI cache"""
        try:
            self.cache = {}
            if os.path.exists(self.cache_file):
                os.remove(self.cache_file)
            logger.info("✅ AI cache cleared successfully")
            return True
        except Exception as e:
            logger.error(f"❌ Error clearing AI cache: {e}")
            return False
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            valid_entries = sum(1 for entry in self.cache.values() if self._is_cache_valid(entry))
            expired_entries = len(self.cache) - valid_entries
            
            return {
                'total_entries': len(self.cache),
                'valid_entries': valid_entries,
                'expired_entries': expired_entries,
                'cache_size_mb': os.path.getsize(self.cache_file) / (1024 * 1024) if os.path.exists(self.cache_file) else 0
            }
        except Exception as e:
            logger.error(f"❌ Error getting cache stats: {e}")
            return {
                'total_entries': 0,
                'valid_entries': 0,
                'expired_entries': 0,
                'cache_size_mb': 0
            }
    
    def cleanup_expired_cache(self) -> int:
        """Remove expired cache entries"""
        try:
            initial_count = len(self.cache)
            expired_keys = [
                key for key, entry in self.cache.items() 
                if not self._is_cache_valid(entry)
            ]
            
            for key in expired_keys:
                del self.cache[key]
            
            if expired_keys:
                self._save_cache()
                logger.info(f"🧹 Cleaned up {len(expired_keys)} expired cache entries")
            
            return len(expired_keys)
            
        except Exception as e:
            logger.error(f"❌ Error cleaning up cache: {e}")
            return 0
