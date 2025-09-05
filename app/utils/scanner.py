"""
Security scanner utility integrating OWASP ZAP and other security testing tools
"""

import requests
import json
import logging
import subprocess
import time
import tempfile
import os
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, quote
from app.config import Config
from app.utils.slack_notifier import slack_notifier

logger = logging.getLogger(__name__)

class SecurityScanner:
    """Main security scanner class"""
    
    def __init__(self, zap_api_url: str = None, zap_api_key: str = None):
        self.zap_api_url = zap_api_url or Config.ZAP_API_URL
        self.zap_api_key = zap_api_key or Config.ZAP_API_KEY
        self.session = requests.Session()
        
        # External tool paths
        self.sqlmap_path = Config.SQLMAP_PATH
        self.ssrfmap_path = Config.SSRFMAP_PATH
        self.xsstrike_path = Config.XSSTRIKE_PATH
        self.nuclei_path = Config.NUCLEI_PATH
        
        # Setup authorization headers
        self._setup_authorization_headers()
    
    def _setup_authorization_headers(self):
        """Setup authorization headers for API requests"""
        logger.info("🔧 Setting up authorization headers...")
        self.auth_headers = {}
        
        # Parse additional headers from config
        logger.info(f"   Config API_HEADERS: {Config.API_HEADERS}")
        try:
            additional_headers = json.loads(Config.API_HEADERS)
            self.auth_headers.update(additional_headers)
            logger.info(f"   ✅ Parsed additional headers: {list(additional_headers.keys())}")
        except (json.JSONDecodeError, TypeError) as e:
            logger.warning(f"   ⚠️  Invalid API_HEADERS configuration: {e}, using defaults")
            self.auth_headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        
        # Add authorization header if configured
        logger.info(f"   Config API_AUTHORIZATION_HEADER: {'***' if Config.API_AUTHORIZATION_HEADER else 'None'}")
        logger.info(f"   Config API_AUTHORIZATION_TYPE: {Config.API_AUTHORIZATION_TYPE}")
        
        if Config.API_AUTHORIZATION_HEADER:
            auth_type = Config.API_AUTHORIZATION_TYPE
            auth_value = Config.API_AUTHORIZATION_HEADER
            
            if auth_type.lower() == 'bearer':
                self.auth_headers['Authorization'] = f'Bearer {auth_value}'
            elif auth_type.lower() == 'basic':
                self.auth_headers['Authorization'] = f'Basic {auth_value}'
            else:
                # Custom authorization type
                self.auth_headers['Authorization'] = f'{auth_type} {auth_value}'
            
            logger.info(f"   ✅ Authorization header configured: {auth_type}")
        else:
            logger.info("   ℹ️  No authorization header configured")
        
        logger.info(f"   📋 Final headers: {list(self.auth_headers.keys())}")
    
    def get_auth_headers(self) -> Dict[str, str]:
        """Get authorization headers for API requests"""
        return self.auth_headers.copy()
    
    def scan_endpoint(self, endpoint: Dict, param_values: Dict, scan_type: str = 'combined') -> Dict:
        """
        Perform security scan on an endpoint
        
        Args:
            endpoint: Endpoint information
            param_values: Parameter values to use
            scan_type: Type of scan (zap, sqlmap, ssrfmap, xsstrike, combined)
            
        Returns:
            Scan results dictionary
        """
        # Note: Scan notifications are handled by the calling task
        # to avoid duplicate notifications
        
        scan_results = {
            'scan_type': scan_type,
            'endpoint': endpoint,
            'param_values': param_values,
            'vulnerabilities': [],
            'scan_time': datetime.now(timezone.utc),
            'duration': 0,
            'status': 'completed',
            'tools_used': []
        }
        
        start_time = time.time()
        
        try:
            if scan_type in ['zap', 'combined']:
                try:
                    zap_results = self._run_zap_scan(endpoint, param_values)
                    scan_results['vulnerabilities'].extend(zap_results.get('vulnerabilities', []))
                    scan_results['tools_used'].append('zap')
                    if zap_results.get('partial_scan'):
                        logger.info("⚠️ ZAP scan completed partially - some components failed")
                except Exception as e:
                    logger.warning(f"ZAP scan failed: {e}")
                    scan_results['tools_used'].append('zap(failed)')
            
            if scan_type in ['sqlmap', 'combined']:
                try:
                    sqlmap_results = self._run_sqlmap_scan(endpoint, param_values)
                    scan_results['vulnerabilities'].extend(sqlmap_results.get('vulnerabilities', []))
                    scan_results['tools_used'].append('sqlmap')
                except Exception as e:
                    logger.warning(f"SQLMap scan failed: {e}")
                    scan_results['tools_used'].append('sqlmap(failed)')
            
            if scan_type in ['ssrfmap', 'combined']:
                try:
                    ssrfmap_results = self._run_ssrfmap_scan(endpoint, param_values)
                    scan_results['vulnerabilities'].extend(ssrfmap_results.get('vulnerabilities', []))
                    scan_results['tools_used'].append('ssrfmap')
                except Exception as e:
                    logger.warning(f"SSRFMap scan failed: {e}")
                    scan_results['tools_used'].append('ssrfmap(failed)')
            
            if scan_type in ['xsstrike', 'combined']:
                try:
                    xsstrike_results = self._run_xsstrike_scan(endpoint, param_values)
                    scan_results['vulnerabilities'].extend(xsstrike_results.get('vulnerabilities', []))
                    scan_results['tools_used'].append('xsstrike')
                except Exception as e:
                    logger.warning(f"XSStrike scan failed: {e}")
                    scan_results['tools_used'].append('xsstrike(failed)')
            
            if scan_type in ['nuclei', 'combined']:
                try:
                    nuclei_results = self._run_nuclei_scan(endpoint, param_values)
                    scan_results['vulnerabilities'].extend(nuclei_results.get('vulnerabilities', []))
                    scan_results['tools_used'].append('nuclei')
                except Exception as e:
                    logger.warning(f"Nuclei scan failed: {e}")
                    scan_results['tools_used'].append('nuclei(failed)')
            
            scan_results['duration'] = time.time() - start_time
            
            # Check if any tools succeeded
            successful_tools = [tool for tool in scan_results['tools_used'] if not tool.endswith('(failed)')]
            if not successful_tools:
                scan_results['status'] = 'failed'
                scan_results['error'] = 'All security tools failed'
            else:
                scan_results['status'] = 'completed'
                logger.info(f"✅ Scan completed with {len(successful_tools)} successful tools: {successful_tools}")
                
        except Exception as e:
            logger.error(f"Scan failed for endpoint {endpoint.get('path')}: {e}")
            scan_results['status'] = 'failed'
            scan_results['error'] = str(e)
            scan_results['duration'] = time.time() - start_time
            
            # Send system error notification
            slack_notifier.send_system_error(
                "Scan Failed",
                f"Scan failed for {endpoint.get('path')}: {e}",
                {'endpoint': endpoint.get('path'), 'scan_type': scan_type}
            )
        
        # Note: Scan completion and vulnerability notifications are handled by the calling task
        # to avoid duplicate notifications
        
        return scan_results
    
    def _run_zap_scan(self, endpoint: Dict, param_values: Dict) -> Dict:
        """Run OWASP ZAP scan with enhanced curl-based information gathering"""
        try:
            # Check if ZAP is available
            if not self._check_zap_availability():
                logger.warning("❌ ZAP not available, skipping scan")
                return {'vulnerabilities': [], 'skipped': 'ZAP not available'}
            
            # Build target URL
            target_url = self._build_target_url(endpoint, param_values)
            logger.info(f"🔍 Starting ZAP scan for: {target_url}")
            
            # Get authorization headers
            auth_headers = self.get_auth_headers()
            
            # Enhanced information gathering using curl before ZAP scan
            endpoint_info = self._gather_endpoint_information_with_curl(target_url, auth_headers, endpoint, param_values)
            logger.info(f"📊 Endpoint information gathered: {endpoint_info.get('status_code', 'Unknown')} status, {len(endpoint_info.get('headers', {}))} headers")
            
            # Configure ZAP context with authorization headers
            context_id = self._setup_zap_context_with_headers(auth_headers)
            
            # Get the context name we're using
            contexts = self._zap_request('context/view/contextList')
            context_list = contexts.get('contextList', [])
            context_name = context_list[0] if context_list else 'api_context'
            
            # Add target URL to ZAP context
            try:
                # Add the specific target URL to context
                self._zap_request('context/action/includeInContext', {
                    'contextName': context_name,
                    'regex': f'.*{target_url.split("/")[2]}.*'  # Extract domain from URL
                })
                
                # Also add the specific URL pattern
                self._zap_request('context/action/includeInContext', {
                    'contextName': context_name,
                    'regex': f'.*{target_url.replace("https://", "").replace("http://", "")}.*'
                })
                
                # Add the exact URL to context
                self._zap_request('context/action/includeInContext', {
                    'contextName': context_name,
                    'regex': f'.*{target_url}.*'
                })
                
                # Wait a moment for context to update
                time.sleep(2)
                
                # Verify URL is in context
                if not self._verify_url_in_context(context_name, target_url):
                    logger.warning("⚠️ Target URL not in context, attempting to add again...")
                    # Try one more time with a broader pattern
                    self._zap_request('context/action/includeInContext', {
                        'contextName': context_name,
                        'regex': '.*'  # Include everything temporarily
                    })
                    time.sleep(1)
                
                logger.info(f"✅ Added target URL to ZAP context: {target_url}")
            except Exception as context_error:
                logger.warning(f"Failed to add URL to context: {context_error}")
            
            # Add target to ZAP spider with enhanced configuration
            try:
                spider_params = {
                    'url': target_url,
                    'contextName': context_name,  # Use contextName for consistency
                    'maxDepth': str(Config.ZAP_SPIDER_DEPTH),
                    'maxChildren': str(Config.ZAP_MAX_CHILDREN),
                    'threadCount': '5'
                }
                
                self._zap_request('spider/action/scan', spider_params)
                logger.info(f"🕷️ ZAP spider started with depth {Config.ZAP_SPIDER_DEPTH}, max children {Config.ZAP_MAX_CHILDREN}")
                
                # Wait for spider to complete
                self._wait_for_spider_completion()
            except Exception as spider_error:
                logger.warning(f"Spider scan failed, continuing with active scan: {spider_error}")
            
            # Run active scan with enhanced configuration
            try:
                # First, check what scan policies are available
                try:
                    policies_response = self._zap_request('ascan/view/scanPolicyNames')
                    available_policies = policies_response.get('scanPolicyNames', [])
                    logger.info(f"📋 Available ZAP scan policies: {available_policies}")
                    
                    # Use the first available policy, or 'Default Policy' if it exists
                    scan_policy = None
                    if 'Default Policy' in available_policies:
                        scan_policy = 'Default Policy'
                    elif available_policies:
                        scan_policy = available_policies[0]
                    else:
                        logger.warning("⚠️ No scan policies available, skipping active scan")
                        return {'vulnerabilities': [], 'skipped': 'No scan policies available'}
                        
                except Exception as e:
                    logger.warning(f"⚠️ Could not get scan policies: {e}, trying without policy")
                    scan_policy = None
                
                ascan_params = {
                    'url': target_url,
                    'contextName': context_name,  # Use contextName instead of contextId for better compatibility
                    'threadCount': '5'
                }
                
                # Only add scanPolicyName if we have a valid policy
                if scan_policy:
                    ascan_params['scanPolicyName'] = scan_policy
                
                self._zap_request('ascan/action/scan', ascan_params)
                logger.info(f"⚡ ZAP active scan started with policy: {scan_policy or 'default'}")
                
                # Wait for active scan to complete
                self._wait_for_ascan_completion()
            except Exception as ascan_error:
                logger.warning(f"Active scan failed: {ascan_error}")
                # Continue with spider results and endpoint info instead of failing completely
            
            # Get alerts (even if active scan failed)
            alerts = []
            try:
                alerts = self._get_zap_alerts()
            except Exception as alert_error:
                logger.warning(f"Failed to get ZAP alerts: {alert_error}")
            
            # Convert alerts to vulnerabilities with enhanced information
            vulnerabilities = self._convert_zap_alerts_to_vulnerabilities(alerts, endpoint_info, endpoint)
            
            # Return results even if some parts failed
            return {
                'vulnerabilities': vulnerabilities,
                'alerts_count': len(alerts),
                'endpoint_info': endpoint_info,
                'zap_context': context_name,
                'partial_scan': len(alerts) == 0  # Indicate if this was a partial scan
            }
            
        except Exception as e:
            logger.error(f"ZAP scan failed: {e}")
            return {'vulnerabilities': [], 'error': str(e)}
    
    def _run_sqlmap_scan(self, endpoint: Dict, param_values: Dict) -> Dict:
        """Run SQLMap scan for SQL injection"""
        try:
            # Check if SQLMap is available
            if not self._check_sqlmap_availability():
                logger.warning("❌ SQLMap not available, skipping scan")
                return {'vulnerabilities': [], 'skipped': 'SQLMap not available'}
            
            # Check if endpoint has database-like parameters
            if not self._has_database_parameters(endpoint, param_values):
                return {'vulnerabilities': [], 'skipped': 'No database parameters'}
            
            # Build target URL
            target_url = self._build_target_url(endpoint, param_values)
            
            # Get authorization headers
            auth_headers = self.get_auth_headers()
            
            # Create a proper request file for SQLMap
            request_file = tempfile.NamedTemporaryFile(mode='w', suffix='.req', delete=False)
            try:
                # Parse URL components
                parsed_url = urlparse(target_url)
                host = parsed_url.netloc
                path = parsed_url.path
                query = parsed_url.query
                
                # Build request file content
                method = endpoint.get('method', 'GET').upper()
                request_content = f"{method} {path}"
                if query:
                    request_content += f"?{query}"
                request_content += " HTTP/1.1\n"
                
                # Add host header
                request_content += f"Host: {host}\n"
                
                # Add authorization headers
                for header_name, header_value in auth_headers.items():
                    request_content += f"{header_name}: {header_value}\n"
                
                # Add default headers
                request_content += "User-Agent: SQLMap/1.0\n"
                request_content += "Accept: */*\n"
                request_content += "Accept-Language: en-US,en;q=0.9\n"
                request_content += "Accept-Encoding: gzip, deflate\n"
                request_content += "Connection: close\n"
                
                # Add body for POST requests
                if method == 'POST':
                    if param_values.get('request_body'):
                        body_data = json.dumps(param_values['request_body'])
                        request_content += f"Content-Type: application/json\n"
                        request_content += f"Content-Length: {len(body_data)}\n\n"
                        request_content += body_data
                    else:
                        # Create form data from parameters
                        form_data = "&".join([f"{k}={v}" for k, v in param_values.items() if v])
                        if form_data:
                            request_content += "Content-Type: application/x-www-form-urlencoded\n"
                            request_content += f"Content-Length: {len(form_data)}\n\n"
                            request_content += form_data
                        else:
                            request_content += "\n"
                else:
                    request_content += "\n"
                
                request_file.write(request_content)
                request_file.close()
                
                logger.info(f"Created SQLMap request file: {request_file.name}")
                logger.debug(f"Request file content:\n{request_content}")
                
                # Create SQLMap command using the request file
                cmd = [
                    self.sqlmap_path,
                    '-r', request_file.name,  # Use request file
                    '--batch',  # Non-interactive mode
                    '--random-agent',  # Random user agent
                    '--level', str(Config.SQLMAP_LEVEL),  # Configurable scan level
                    '--risk', str(Config.SQLMAP_RISK),    # Configurable risk level
                    '--threads', str(Config.SQLMAP_THREADS),  # Configurable threads
                    '--timeout', str(Config.SQLMAP_TIMEOUT),  # Configurable timeout
                    '--output-dir', tempfile.gettempdir() + '/sqlmap_output',
                    '--smart',  # Smart optimization
                    '--technique', 'BEUSTQ',  # All SQL injection techniques
                    '--dbms', 'mysql,postgresql,oracle,mssql,sqlite',  # Test multiple DBMS
                    '--os', 'linux,windows',  # Test multiple OS
                    '--hpp',  # HTTP Parameter Pollution
                    '--fresh-queries',  # Don't use cached queries
                    '--cleanup'  # Clean up temporary files
                ]
                
                # Add custom headers if needed
                if auth_headers:
                    logger.info(f"Added {len(auth_headers)} authorization headers to SQLMap scan")
                
                logger.info(f"Running SQLMap with command: {' '.join(cmd)}")
                
                # Run SQLMap
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                # Parse results
                vulnerabilities = self._parse_sqlmap_results(result.stdout, result.stderr)
                
                return {
                    'vulnerabilities': vulnerabilities,
                    'command': ' '.join(cmd),
                    'exit_code': result.returncode,
                    'request_file': request_file.name
                }
                
            finally:
                # Clean up request file
                try:
                    os.unlink(request_file.name)
                    logger.info(f"Cleaned up request file: {request_file.name}")
                except Exception as e:
                    logger.warning(f"Failed to clean up request file: {e}")
            
        except Exception as e:
            logger.error(f"SQLMap scan failed: {e}")
            return {'vulnerabilities': [], 'error': str(e)}
    
    def _run_ssrfmap_scan(self, endpoint: Dict, param_values: Dict) -> Dict:
        """Run SSRFMap scan for SSRF vulnerabilities"""
        try:
            # Check if endpoint has URL parameters
            if not self._has_url_parameters(endpoint, param_values):
                return {'vulnerabilities': [], 'skipped': 'No URL parameters'}
            
            # Build target URL
            target_url = self._build_target_url(endpoint, param_values)
            
            # Get authorization headers
            auth_headers = self.get_auth_headers()
            
            # Create a temporary request file for SSRFMap
            request_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
            try:
                # Write request content to file
                request_content = f"""POST {endpoint.get('path', '/')} HTTP/1.1
Host: {target_url.split('/')[2]}
User-Agent: SSRFmap/1.0
Accept: */*
Content-Type: application/json
Content-Length: 100

{json.dumps(param_values)}"""
                
                request_file.write(request_content)
                request_file.close()
                
                # Create SSRFMap command (using correct format)
                cmd = [
                    'python', self.ssrfmap_path,
                    '-r', request_file.name,
                    '-p', 'url',  # Parameter to test
                    '-m', 'portscan,redis,aws,ec2',  # Modules to run
                    '--level', '1'  # Basic level
                ]
                
                # Run SSRFMap
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd='./SSRFmap')
                
                # Parse results
                vulnerabilities = self._parse_ssrfmap_results(result.stdout, result.stderr)
                
                return {
                    'vulnerabilities': vulnerabilities,
                    'command': ' '.join(cmd),
                    'exit_code': result.returncode
                }
                
            finally:
                # Clean up temporary file
                if os.path.exists(request_file.name):
                    os.unlink(request_file.name)
            
        except Exception as e:
            logger.error(f"SSRFMap scan failed: {e}")
            return {'vulnerabilities': [], 'error': str(e)}
    
    def _run_xsstrike_scan(self, endpoint: Dict, param_values: Dict) -> Dict:
        """Run XSStrike scan for XSS vulnerabilities"""
        try:
            # Check if endpoint has string parameters
            if not self._has_string_parameters(endpoint, param_values):
                return {'vulnerabilities': [], 'skipped': 'No string parameters'}
            
            # Build target URL
            target_url = self._build_target_url(endpoint, param_values)
            
            # Get authorization headers
            auth_headers = self.get_auth_headers()
            
            # Create XSStrike command
            cmd = [
                self.xsstrike_path,
                '-u', target_url,
                '--skip-dom',  # Skip DOM XSS
                '--blind',  # Blind XSS
                '--skip-poc',  # Skip proof of concept
                '--output', tempfile.gettempdir() + '/xsstrike_output'
            ]
            
            # Run XSStrike
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse results
            vulnerabilities = self._parse_xsstrike_results(result.stdout, result.stderr)
            
            return {
                'vulnerabilities': vulnerabilities,
                'command': ' '.join(cmd),
                'exit_code': result.returncode
            }
            
        except Exception as e:
            logger.error(f"XSStrike scan failed: {e}")
            return {'vulnerabilities': [], 'error': str(e)}
    
    def _build_target_url(self, endpoint: Dict, param_values: Dict) -> str:
        """Build target URL with parameters"""
        from urllib.parse import quote
        
        # Use service API URL if available, otherwise fall back to base URL
        if endpoint.get('service_api_url'):
            # Remove /v3/api-docs from the service URL to get the actual API base URL
            service_url = endpoint['service_api_url'].rstrip('/')
            if service_url.endswith('/v3/api-docs'):
                base_url = service_url[:-12]  # Remove '/v3/api-docs'
            else:
                base_url = service_url
        else:
            base_url = Config.API_BASE_URL.rstrip('/')
        
        path = endpoint.get('path', '')
        
        # Replace path parameters with proper URL encoding
        for param_name, param_value in param_values.items():
            if param_name in path:
                # Properly encode the parameter value for URL
                encoded_value = quote(str(param_value), safe='')
                path = path.replace(f'{{{param_name}}}', encoded_value)
        
        # Add query parameters with proper URL encoding
        query_params = []
        for param_name, param_value in param_values.items():
            if param_name not in path and param_name != 'request_body':
                # Properly encode both parameter name and value
                encoded_name = quote(str(param_name), safe='')
                encoded_value = quote(str(param_value), safe='')
                query_params.append(f"{encoded_name}={encoded_value}")
        
        url = f"{base_url}{path}"
        if query_params:
            url += '?' + '&'.join(query_params)
        
        return url
    
    def _zap_request(self, endpoint: str, params: Dict = None) -> Dict:
        """Make request to ZAP API"""
        url = f"{self.zap_api_url}/JSON/{endpoint}"
        
        # Ensure params is a dictionary
        if params is None:
            params = {}
        
        # Always include the API key
        if self.zap_api_key:
            params['apikey'] = self.zap_api_key
        else:
            logger.warning("⚠️ No ZAP API key configured")
        
        try:
            logger.debug(f"🔍 Making ZAP API request to: {endpoint}")
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.debug(f"✅ ZAP API response for {endpoint}: {result}")
            
            # Check for ZAP API errors
            if 'code' in result and result['code'] != 'OK':
                logger.warning(f"⚠️ ZAP API returned error code: {result.get('code')} - {result.get('message', 'Unknown error')}")
                if result.get('code') == 'bad_view':
                    logger.warning(f"   This might be a ZAP version compatibility issue with endpoint: {endpoint}")
            
            return result
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ ZAP API request failed for {endpoint}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"   Response status: {e.response.status_code}")
                logger.error(f"   Response text: {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"❌ Unexpected error in ZAP API request for {endpoint}: {e}")
            raise
    
    def _setup_zap_context(self) -> str:
        """Setup ZAP context for scanning"""
        try:
            # First check if context already exists
            contexts = self._zap_request('context/view/contextList')
            
            # Handle both old and new ZAP API response formats
            if 'contextList' in contexts:
                # New format (ZAP 2.12+) - context list is nested
                context_list = contexts['contextList']
            else:
                # Old format or fallback
                context_list = contexts.get('contextList', [])
            
            # Try to use existing context if available
            if context_list:
                # Use the first available context
                context_name = context_list[0]
                logger.info(f"Using existing ZAP context: {context_name}")
                try:
                    context_info = self._zap_request('context/view/context', {
                        'contextName': context_name
                    })
                    
                    # Handle both old and new ZAP API response formats
                    if 'context' in context_info:
                        # New format (ZAP 2.12+) - context info is nested
                        context_data = context_info['context']
                        context_id = context_data.get('id', '1')
                    else:
                        # Old format or fallback
                        context_id = context_info.get('contextId', '1')
                    
                    logger.info(f"Using context ID: {context_id}")
                    
                    # Ensure the context is properly configured
                    self._zap_request('context/action/setContextInScope', {
                        'contextName': context_name,
                        'booleanInScope': 'true'
                    })
                    
                    return context_id
                except Exception as e:
                    logger.warning(f"Failed to get context info for {context_name}: {e}")
                    
                    # Check if it's a "bad_view" error and try alternative approach
                    if 'bad_view' in str(e).lower() or 'bad view' in str(e).lower():
                        logger.info(f"Attempting to use context name directly for {context_name}")
                        # For bad_view errors, try to use the context name directly
                        # This works in some ZAP versions where the view endpoint is problematic
                        try:
                            # Try to set the context in scope directly
                            self._zap_request('context/action/setContextInScope', {
                                'contextName': context_name,
                                'booleanInScope': 'true'
                            })
                            logger.info(f"Successfully configured context {context_name} using direct action")
                            return '1'  # Use default context ID
                        except Exception as fallback_error:
                            logger.warning(f"Fallback context setup also failed: {fallback_error}")
                    
                    # Fall through to create new context
            
            # Try to create a simple context
            logger.info("Creating new ZAP context: api_context")
            try:
                context_response = self._zap_request('context/action/newContext', {
                    'contextName': 'api_context'
                })
                logger.info("Successfully created api_context")
                
                # Get context ID for the newly created context
                try:
                    context_info = self._zap_request('context/view/context', {
                        'contextName': 'api_context'
                    })
                    
                    # Handle both old and new ZAP API response formats
                    if 'context' in context_info:
                        # New format (ZAP 2.12+) - context info is nested
                        context_data = context_info['context']
                        context_id = context_data.get('id', '1')
                    else:
                        # Old format or fallback
                        context_id = context_info.get('contextId', '1')
                    
                    logger.info(f"Created context ID: {context_id}")
                except Exception as context_view_error:
                    logger.warning(f"Failed to get context info for newly created context: {context_view_error}")
                    
                    # Check if it's a "bad_view" error and use fallback
                    if 'bad_view' in str(context_view_error).lower() or 'bad view' in str(context_view_error).lower():
                        logger.info("Using fallback context ID due to bad_view error")
                        context_id = '1'  # Use default context ID
                    else:
                        # For other errors, raise the exception
                        raise context_view_error
                
                # Ensure the context is properly configured
                self._zap_request('context/action/setContextInScope', {
                    'contextName': 'api_context',
                    'booleanInScope': 'true'
                })
                
                return context_id
            except Exception as context_error:
                logger.warning(f"Failed to create context: {context_error}")
                # Fall back to default context
                return '1'
            
        except Exception as e:
            logger.warning(f"Failed to setup ZAP context: {e}")
            return '1'
    
    def _setup_zap_context_with_headers(self, auth_headers: Dict[str, str]) -> str:
        """Setup ZAP context with authorization headers"""
        try:
            # Create context
            context_id = self._setup_zap_context()
            
            # Get the context name we're using
            contexts = self._zap_request('context/view/contextList')
            
            # Handle both old and new ZAP API response formats
            if 'contextList' in contexts:
                # New format (ZAP 2.12+) - context list is nested
                context_list = contexts['contextList']
            else:
                # Old format or fallback
                context_list = contexts.get('contextList', [])
            
            context_name = context_list[0] if context_list else 'api_context'
            
            # Add authorization headers to context if configured
            if auth_headers:
                for header_name, header_value in auth_headers.items():
                    try:
                        self._zap_request('context/action/includeInContext', {
                            'contextName': context_name,
                            'regex': f'.*{header_name}.*'
                        })
                        
                        # Add header to context
                        self._zap_request('context/action/setContextInScope', {
                            'contextName': context_name,
                            'booleanInScope': 'true'
                        })
                        
                        logger.info(f"Added header {header_name} to ZAP context")
                    except Exception as e:
                        logger.warning(f"Failed to add header {header_name} to ZAP context: {e}")
            
            return context_id
            
        except Exception as e:
            logger.warning(f"Failed to setup ZAP context with headers: {e}")
            return self._setup_zap_context()
    
    def _wait_for_spider_completion(self, timeout: int = 300):
        """Wait for ZAP spider to complete"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                status = self._zap_request('spider/view/status')
                
                # Handle both old and new ZAP API response formats
                if 'spiderStatus' in status:
                    # New format (ZAP 2.12+) - status is nested
                    spider_status = status['spiderStatus'].get('status', '0')
                else:
                    # Old format or fallback
                    spider_status = status.get('status', '0')
                
                if spider_status == '100':
                    break
                time.sleep(5)
            except Exception:
                time.sleep(5)
    
    def _wait_for_ascan_completion(self, timeout: int = 600):
        """Wait for ZAP active scan to complete"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                status = self._zap_request('ascan/view/status')
                
                # Handle both old and new ZAP API response formats
                if 'ascanStatus' in status:
                    # New format (ZAP 2.12+) - status is nested
                    ascan_status = status['ascanStatus'].get('status', '0')
                else:
                    # Old format or fallback
                    ascan_status = status.get('status', '0')
                
                if ascan_status == '100':
                    break
                time.sleep(10)
            except Exception:
                time.sleep(10)
    
    def _get_zap_alerts(self) -> List[Dict]:
        """Get alerts from ZAP"""
        try:
            alerts = self._zap_request('core/view/alerts')
            
            # Handle both old and new ZAP API response formats
            if 'alerts' in alerts:
                # New format (ZAP 2.12+) - alerts are nested
                return alerts['alerts']
            else:
                # Old format or fallback
                return alerts.get('alerts', [])
        except Exception as e:
            logger.error(f"Failed to get ZAP alerts: {e}")
            return []
    
    def _convert_zap_alerts_to_vulnerabilities(self, alerts: List[Dict], endpoint_info: Dict = None, endpoint: Dict = None) -> List[Dict]:
        """Convert ZAP alerts to vulnerability format with enhanced endpoint information"""
        vulnerabilities = []
        
        for alert in alerts:
            # Map ZAP risk levels to our severity levels
            risk_mapping = {
                'High': 'high',
                'Medium': 'medium',
                'Low': 'low',
                'Informational': 'info'
            }
            
            severity = risk_mapping.get(alert.get('risk'), 'medium')
            
            # Enhanced vulnerability details with endpoint information
            vulnerability_details = {
                'url': alert.get('url', ''),
                'parameter': alert.get('parameter', ''),
                'attack': alert.get('attack', ''),
                'confidence': alert.get('confidence', ''),
                'cweid': alert.get('cweid', ''),
                'wascid': alert.get('wascid', ''),
                'tool': 'zap'
            }
            
            # Add endpoint information if available
            if endpoint_info:
                vulnerability_details.update({
                    'endpoint_method': endpoint_info.get('method'),
                    'endpoint_status_code': endpoint_info.get('status_code'),
                    'endpoint_response_size': endpoint_info.get('response_size'),
                    'endpoint_response_time': endpoint_info.get('response_time'),
                    'endpoint_headers': endpoint_info.get('headers', {}),
                    'endpoint_security_headers': endpoint_info.get('security_headers', {}),
                    'endpoint_ssl_info': endpoint_info.get('ssl_info', {}),
                    'endpoint_server_info': endpoint_info.get('server_info'),
                    'endpoint_content_type': endpoint_info.get('content_type'),
                    'curl_command_used': endpoint_info.get('curl_command')
                })
            
            vulnerability = {
                'name': alert.get('name', 'Unknown Vulnerability'),
                'description': alert.get('description', ''),
                'severity': severity,
                'category': self._map_zap_alert_to_category(alert.get('name', '')),
                'evidence': alert.get('evidence', ''),
                'endpoint_path': endpoint.get('path', 'Unknown') if endpoint else 'Unknown',
                'endpoint_method': endpoint.get('method', 'Unknown') if endpoint else 'Unknown',
                'tool': 'zap',
                'details': vulnerability_details
            }
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _map_zap_alert_to_category(self, alert_name: str) -> str:
        """Map ZAP alert name to vulnerability category"""
        alert_lower = alert_name.lower()
        
        if 'sql' in alert_lower and 'injection' in alert_lower:
            return 'sql_injection'
        elif 'xss' in alert_lower or 'cross-site' in alert_lower:
            return 'xss'
        elif 'ssrf' in alert_lower or 'server-side' in alert_lower:
            return 'ssrf'
        elif 'csrf' in alert_lower or 'cross-site request forgery' in alert_lower:
            return 'csrf'
        elif 'injection' in alert_lower:
            return 'injection'
        elif 'authentication' in alert_lower or 'auth' in alert_lower:
            return 'authentication'
        elif 'authorization' in alert_lower:
            return 'authorization'
        elif 'information disclosure' in alert_lower:
            return 'information_disclosure'
        elif 'misconfiguration' in alert_lower:
            return 'misconfiguration'
        else:
            return 'other'
    
    def _has_database_parameters(self, endpoint: Dict, param_values: Dict) -> bool:
        """Check if endpoint has database-like parameters"""
        # Check parameter names for database indicators
        db_keywords = ['id', 'user_id', 'product_id', 'order_id', 'customer_id', 'query', 'search', 'filter']
        
        for param_name in param_values.keys():
            if any(keyword in param_name.lower() for keyword in db_keywords):
                return True
        
        return False
    
    def _has_url_parameters(self, endpoint: Dict, param_values: Dict) -> bool:
        """Check if endpoint has URL parameters"""
        url_keywords = ['url', 'uri', 'link', 'redirect', 'callback', 'webhook']
        
        for param_name in param_values.keys():
            if any(keyword in param_name.lower() for keyword in url_keywords):
                return True
        
        return False
    
    def _has_string_parameters(self, endpoint: Dict, param_values: Dict) -> bool:
        """Check if endpoint has string parameters"""
        for param_name, param_value in param_values.items():
            if isinstance(param_value, str) and param_name != 'request_body':
                return True
        
        return False
    
    def _parse_sqlmap_results(self, stdout: str, stderr: str) -> List[Dict]:
        """Parse SQLMap results"""
        vulnerabilities = []
        
        # Look for SQL injection findings
        if 'sqlmap identified the following injection point' in stdout:
            vulnerability = {
                'name': 'SQL Injection',
                'description': 'SQL injection vulnerability detected by SQLMap',
                'severity': 'high',
                'category': 'sql_injection',
                'evidence': stdout,
                'endpoint_path': 'Unknown',  # SQLMap doesn't have endpoint context
                'endpoint_method': 'Unknown',
                'tool': 'sqlmap',
                'details': {
                    'tool': 'sqlmap',
                    'stdout': stdout,
                    'stderr': stderr
                }
            }
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _parse_ssrfmap_results(self, stdout: str, stderr: str) -> List[Dict]:
        """Parse SSRFMap results"""
        vulnerabilities = []
        
        # Look for SSRF findings
        if 'vulnerable' in stdout.lower() or 'ssrf' in stdout.lower():
            vulnerability = {
                'name': 'Server-Side Request Forgery',
                'description': 'SSRF vulnerability detected by SSRFMap',
                'severity': 'high',
                'category': 'ssrf',
                'evidence': stdout,
                'endpoint_path': 'Unknown',  # SSRFMap doesn't have endpoint context
                'endpoint_method': 'Unknown',
                'tool': 'ssrfmap',
                'details': {
                    'tool': 'ssrfmap',
                    'stdout': stdout,
                    'stderr': stderr
                }
            }
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _parse_xsstrike_results(self, stdout: str, stderr: str) -> List[Dict]:
        """Parse XSStrike results"""
        vulnerabilities = []
        
        # Look for XSS findings
        if 'vulnerable' in stdout.lower() or 'xss' in stdout.lower():
            vulnerability = {
                'name': 'Cross-Site Scripting',
                'description': 'XSS vulnerability detected by XSStrike',
                'severity': 'medium',
                'category': 'xss',
                'evidence': stdout,
                'endpoint_path': 'Unknown',  # XSStrike doesn't have endpoint context
                'endpoint_method': 'Unknown',
                'tool': 'xsstrike',
                'details': {
                    'tool': 'xsstrike',
                    'stdout': stdout,
                    'stderr': stderr
                }
            }
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _run_nuclei_scan(self, endpoint: Dict, param_values: Dict) -> Dict:
        """Run Nuclei scan with proper HTTP method support"""
        try:
            # Build target URL
            target_url = self._build_target_url(endpoint, param_values)
            method = endpoint.get('method', 'GET').upper()
            logger.info(f"🔍 Starting Nuclei scan for endpoint: {endpoint.get('path')}")
            logger.info(f"   Target URL: {target_url}")
            logger.info(f"   Method: {method}")
            logger.info(f"   Parameters: {param_values}")
            
            # Check if Nuclei is available
            if not self._check_nuclei_availability():
                logger.warning("❌ Nuclei not available, skipping scan")
                return {'vulnerabilities': []}
            
            # Get authorization headers
            auth_headers = self.get_auth_headers()
            logger.info(f"🔐 Authorization headers: {auth_headers}")
            
            # Create Nuclei command with enhanced options
            cmd = [
                self.nuclei_path,
                '-u', target_url,
                '-t', Config.NUCLEI_TEMPLATES,  # Use configurable templates
                '-severity', Config.NUCLEI_SEVERITY,  # Use configurable severity levels
                '-rate-limit', str(Config.NUCLEI_RATE_LIMIT),  # Rate limiting
                '-c', '50',  # Concurrent requests
                '-timeout', '10',  # Request timeout
                '-retries', '2',  # Retry failed requests
                '-bulk-size', '25',  # Bulk size for scanning
                '-stats',  # Show statistics
                '-silent',  # Silent mode for automation
                '-o', tempfile.gettempdir() + '/nuclei_output.json'  # Output file
            ]
            
            # Add method-specific options
            if method == 'POST':
                cmd.extend(['-H', 'Content-Type: application/json'])
                if param_values.get('request_body'):
                    cmd.extend(['-body', json.dumps(param_values['request_body'])])
            
            # Add authorization headers
            for header_name, header_value in auth_headers.items():
                cmd.extend(['-H', f'{header_name}: {header_value}'])
            
            logger.info(f"🚀 Running Nuclei with command: {' '.join(cmd)}")
            
            # Run Nuclei
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse results
            vulnerabilities = self._parse_nuclei_results(result.stdout, result.stderr, endpoint)
            
            return {
                'vulnerabilities': vulnerabilities,
                'command': ' '.join(cmd),
                'exit_code': result.returncode
            }
            
            # Verify template file exists and has content
            import os
            if os.path.exists(temp_file_path):
                with open(temp_file_path, 'r') as f:
                    template_content_check = f.read()
                logger.info(f"📄 Template file size: {len(template_content_check)} bytes")
            else:
                logger.error(f"❌ Template file not found: {temp_file_path}")
                return {'vulnerabilities': [], 'error': 'Template file not created'}
            
            # Prepare Nuclei command with optimized timeout settings
            nuclei_cmd = [
                self.nuclei_path,
                '-t', temp_file_path,
                '-tags', 'api,swagger,openapi,rest,http',  # API-specific built-in templates
                '-u', target_url,
                '-jsonl',  # Output in JSONL format
                '-silent',  # Silent mode
                '-severity', 'info,low,medium,high,critical',  # All severities including info
                '-timeout', '15',  # Optimized: 15 second timeout (reduced from 20)
                '-rate-limit', '100'  # Optimized: 100 rate limit (reduced from 150)
            ]
            
            logger.info(f"🚀 Executing Nuclei command: {' '.join(nuclei_cmd)}")
            
            # Run Nuclei scan with custom template
            logger.info(f"⏱️  Starting Nuclei subprocess execution...")
            start_time = time.time()
            
            # First run with custom template
            logger.info(f"🔍 Phase 1: Running with custom template...")
            
            try:
                result = subprocess.run(
                    nuclei_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30  # Optimized: 30 second timeout for the entire scan (reduced from 45)
                )
                
                execution_time = time.time() - start_time
                logger.info(f"⏱️  Nuclei execution completed in {execution_time:.2f} seconds")
                logger.info(f"📊 Nuclei return code: {result.returncode}")
                logger.info(f"📄 Nuclei stdout length: {len(result.stdout)} characters")
                logger.info(f"⚠️  Nuclei stderr length: {len(result.stderr)} characters")
                
                if result.stderr:
                    logger.warning(f"⚠️  Nuclei stderr output: {result.stderr}")
                
                # Parse results from custom template
                logger.info(f"🔍 Parsing Nuclei results from custom template...")
                custom_vulnerabilities = self._parse_nuclei_results(result.stdout, result.stderr, endpoint)
                logger.info(f"🎯 Found {len(custom_vulnerabilities)} vulnerabilities from custom template")
                
                # Second phase: Run with built-in API security templates
                logger.info(f"🔍 Phase 2: Running with built-in API security templates...")
                builtin_cmd = [
                    self.nuclei_path,
                    '-tags', 'api,swagger,openapi,rest,http',
                    '-u', target_url,
                    '-jsonl',
                    '-silent',
                    '-severity', 'info,low,medium,high,critical',
                    '-timeout', '15',  # Optimized: 15 second timeout
                    '-rate-limit', '100'  # Optimized: 100 rate limit
                ]
                
                # Add authorization headers to built-in scan
                if auth_headers:
                    for header_name, header_value in auth_headers.items():
                        builtin_cmd.extend(['-H', f'{header_name}: {header_value}'])
                
                logger.info(f"🚀 Executing built-in templates command: {' '.join(builtin_cmd)}")
                
                builtin_result = subprocess.run(
                    builtin_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30  # Optimized: 30 second timeout
                )
                
                logger.info(f"📊 Built-in templates return code: {builtin_result.returncode}")
                logger.info(f"📄 Built-in templates stdout length: {len(builtin_result.stdout)} characters")
                
                # Parse results from built-in templates
                builtin_vulnerabilities = self._parse_nuclei_results(builtin_result.stdout, builtin_result.stderr, endpoint)
                logger.info(f"🎯 Found {len(builtin_vulnerabilities)} vulnerabilities from built-in templates")
                
                # Combine results
                all_vulnerabilities = custom_vulnerabilities + builtin_vulnerabilities
                logger.info(f"🎯 Total vulnerabilities found: {len(all_vulnerabilities)}")
                
                return {
                    'vulnerabilities': all_vulnerabilities,
                    'custom_vulnerabilities': custom_vulnerabilities,
                    'builtin_vulnerabilities': builtin_vulnerabilities,
                    'stdout': result.stdout + "\n" + builtin_result.stdout,
                    'stderr': result.stderr + "\n" + builtin_result.stderr,
                    'return_code': result.returncode
                }
                
            finally:
                # Clean up temporary template file
                try:
                    if os.path.exists(temp_file_path):
                        os.unlink(temp_file_path)
                        logger.info(f"🧹 Cleaned up temporary template file: {temp_file_path}")
                except Exception as e:
                    logger.warning(f"⚠️  Failed to clean up template file: {e}")
            
        except subprocess.TimeoutExpired:
            logger.error(f"Nuclei scan timed out for {target_url}")
            return {
                'vulnerabilities': [],
                'error': 'Scan timed out',
                'stdout': '',
                'stderr': 'Timeout after 45 seconds'
            }
        except Exception as e:
            logger.error(f"Nuclei scan failed for {target_url}: {e}")
            return {
                'vulnerabilities': [],
                'error': str(e),
                'stdout': '',
                'stderr': str(e)
            }
    
    def _create_nuclei_template(self, endpoint: Dict, param_values: Dict, auth_headers: Dict) -> str:
        """Create a comprehensive Nuclei template with multiple security checks"""
        method = endpoint.get('method', 'GET').upper()
        path = endpoint.get('path', '')
        
        # Generate unique template ID
        import uuid
        template_id = f"custom-{uuid.uuid4().hex[:8]}"
        
        # Prepare headers
        headers = []
        if auth_headers:
            for header_name, header_value in auth_headers.items():
                headers.append(f"      {header_name}: {header_value}")
        
        # Prepare request body for POST/PUT/PATCH
        body = ""
        if method in ['POST', 'PUT', 'PATCH'] and param_values.get('request_body'):
            import json
            body = json.dumps(param_values['request_body'])
        
        # Create simplified but effective template
        template = f"""id: {template_id}
info:
  name: API Security Scan - {method} {path}
  author: API Security Scanner
  severity: info
  description: Security scan for {method} {path}
  tags: api,security,{method.lower()}

requests:
  - method: {method}
    path:
      - "{{{{BaseURL}}}}{path}"
"""
        
        # Add headers if present
        if auth_headers:
            template += "    headers:\n"
            for header_name, header_value in auth_headers.items():
                template += f"      {header_name}: {header_value}\n"
        
        # Add body if present
        if body:
            template += f"    body: '{body}'\n"
        
        # Add basic matchers
        template += """
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "error"
          - "exception"
          - "sql"
          - "mysql"
          - "postgresql"
          - "oracle"
          - "syntax error"
          - "stack trace"
        condition: or
      - type: status
        status:
          - 500
          - 502
          - 503
          - 504
      - type: regex
        regex:
          - "(?i)(sql|mysql|postgresql|oracle).*error"
          - "(?i)(syntax|parse).*error"
        condition: or
"""
        
        return template
    
    def _check_nuclei_availability(self) -> bool:
        """Check if Nuclei is available and working"""
        try:
            result = subprocess.run(
                [self.nuclei_path, '-version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_zap_availability(self) -> bool:
        """Check if ZAP is available and working"""
        try:
            # Try to connect to ZAP API with API key
            import requests
            response = requests.get(
                f"{Config.ZAP_API_URL}/JSON/core/view/version", 
                params={'apikey': Config.ZAP_API_KEY},
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"ZAP availability check failed: {e}")
            return False
    
    def _gather_endpoint_information_with_curl(self, target_url: str, auth_headers: Dict, endpoint: Dict, param_values: Dict) -> Dict:
        """Gather comprehensive endpoint information using curl before ZAP scan"""
        endpoint_info = {
            'url': target_url,
            'method': endpoint.get('method', 'GET'),
            'status_code': None,
            'headers': {},
            'response_size': 0,
            'response_time': 0,
            'ssl_info': {},
            'security_headers': {},
            'content_type': None,
            'server_info': None,
            'curl_command': None
        }
        
        try:
            # Build curl command
            method = endpoint.get('method', 'GET').upper()
            curl_cmd = ['curl', '-s', '-w', '%{http_code}|%{size_download}|%{time_total}|%{time_connect}|%{time_namelookup}', '-o', '/tmp/zap_scan_response']
            
            # Add method
            if method != 'GET':
                curl_cmd.extend(['-X', method])
            
            # Add headers
            for header_name, header_value in auth_headers.items():
                curl_cmd.extend(['-H', f'{header_name}: {header_value}'])
            
            # Add common headers for better information gathering
            curl_cmd.extend(['-H', 'User-Agent: ZAP-Security-Scanner/1.0'])
            curl_cmd.extend(['-H', 'Accept: */*'])
            curl_cmd.extend(['-H', 'Accept-Language: en-US,en;q=0.9'])
            curl_cmd.extend(['-H', 'Accept-Encoding: gzip, deflate'])
            curl_cmd.extend(['-H', 'Connection: close'])
            
            # Add data for POST requests
            if method == 'POST' and param_values:
                if param_values.get('request_body'):
                    curl_cmd.extend(['-H', 'Content-Type: application/json'])
                    curl_cmd.extend(['-d', json.dumps(param_values['request_body'])])
                else:
                    # Create form data
                    form_data = "&".join([f"{k}={v}" for k, v in param_values.items() if v])
                    if form_data:
                        curl_cmd.extend(['-H', 'Content-Type: application/x-www-form-urlencoded'])
                        curl_cmd.extend(['-d', form_data])
            
            # Add target URL
            curl_cmd.append(target_url)
            
            # Store curl command for debugging
            endpoint_info['curl_command'] = ' '.join(curl_cmd)
            
            # Execute curl command
            logger.info(f"🔍 Executing curl command: {' '.join(curl_cmd)}")
            result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Parse curl output
                output_parts = result.stdout.strip().split('|')
                if len(output_parts) >= 5:
                    endpoint_info['status_code'] = int(output_parts[0])
                    endpoint_info['response_size'] = int(output_parts[1])
                    endpoint_info['response_time'] = float(output_parts[2])
                    endpoint_info['connect_time'] = float(output_parts[3])
                    endpoint_info['dns_time'] = float(output_parts[4])
                
                # Get response headers using another curl call
                header_cmd = ['curl', '-s', '-I', '-w', '%{http_code}']
                for header_name, header_value in auth_headers.items():
                    header_cmd.extend(['-H', f'{header_name}: {header_value}'])
                header_cmd.append(target_url)
                
                header_result = subprocess.run(header_cmd, capture_output=True, text=True, timeout=10)
                if header_result.returncode == 0:
                    # Parse headers
                    lines = header_result.stdout.strip().split('\n')
                    for line in lines:
                        if ':' in line and not line.startswith('HTTP/'):
                            key, value = line.split(':', 1)
                            endpoint_info['headers'][key.strip()] = value.strip()
                    
                    # Extract security-relevant information
                    endpoint_info['content_type'] = endpoint_info['headers'].get('Content-Type', '')
                    endpoint_info['server_info'] = endpoint_info['headers'].get('Server', '')
                    
                    # Check for security headers
                    security_headers = [
                        'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options',
                        'X-XSS-Protection', 'Strict-Transport-Security', 'Referrer-Policy'
                    ]
                    
                    for sec_header in security_headers:
                        if sec_header in endpoint_info['headers']:
                            endpoint_info['security_headers'][sec_header] = endpoint_info['headers'][sec_header]
                
                # Check SSL information if HTTPS
                if target_url.startswith('https://'):
                    ssl_cmd = ['curl', '-s', '-I', '--connect-timeout', '10']
                    for header_name, header_value in auth_headers.items():
                        ssl_cmd.extend(['-H', f'{header_name}: {header_value}'])
                    ssl_cmd.append(target_url)
                    
                    ssl_result = subprocess.run(ssl_cmd, capture_output=True, text=True, timeout=15)
                    if ssl_result.returncode == 0:
                        endpoint_info['ssl_info']['https_enabled'] = True
                        # Could add more SSL info parsing here
                    else:
                        endpoint_info['ssl_info']['https_enabled'] = False
                else:
                    endpoint_info['ssl_info']['https_enabled'] = False
                
                logger.info(f"✅ Endpoint information gathered successfully: {endpoint_info['status_code']} status, {len(endpoint_info['headers'])} headers")
                
            else:
                logger.warning(f"⚠️ Curl command failed: {result.stderr}")
                endpoint_info['error'] = result.stderr
                
        except Exception as e:
            logger.error(f"❌ Error gathering endpoint information: {e}")
            endpoint_info['error'] = str(e)
        
        return endpoint_info
    
    def _check_sqlmap_availability(self) -> bool:
        """Check if SQLMap is available and working"""
        try:
            result = subprocess.run(
                [self.sqlmap_path, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _parse_nuclei_results(self, stdout: str, stderr: str, endpoint: Dict = None) -> List[Dict]:
        """Parse Nuclei results from JSON output"""
        vulnerabilities = []
        
        logger.info(f"🔍 Parsing Nuclei output...")
        logger.info(f"   Raw stdout lines: {len(stdout.strip().split('\n')) if stdout.strip() else 0}")
        
        try:
            # Nuclei outputs one JSON object per line
            for i, line in enumerate(stdout.strip().split('\n')):
                if line.strip():
                    try:
                        result = json.loads(line)
                        logger.info(f"   📄 Parsing line {i+1}: {result.get('info', {}).get('name', 'Unknown')}")
                        
                        # Extract vulnerability information
                        vulnerability = {
                            'name': result.get('info', {}).get('name', 'Unknown Vulnerability'),
                            'description': result.get('info', {}).get('description', ''),
                            'severity': result.get('info', {}).get('severity', 'medium').lower(),
                            'category': self._map_nuclei_category(result.get('info', {}).get('tags', [])),
                            'evidence': result.get('matcher-name', ''),
                            'endpoint_path': endpoint.get('path', 'Unknown') if endpoint else 'Unknown',
                            'endpoint_method': endpoint.get('method', 'Unknown') if endpoint else 'Unknown',
                            'tool': 'nuclei',
                            'details': {
                                'tool': 'nuclei',
                                'template_id': result.get('template-id', ''),
                                'template_url': result.get('info', {}).get('reference', []),
                                'matched_at': result.get('matched-at', ''),
                                'extracted_results': result.get('extracted-results', []),
                                'raw_result': result
                            }
                        }
                        
                        # Add CVSS score if available
                        if 'cvss' in result.get('info', {}):
                            vulnerability['cvss_score'] = result['info']['cvss']
                        
                        logger.info(f"   🚨 Found vulnerability: {vulnerability['name']} ({vulnerability['severity']})")
                        vulnerabilities.append(vulnerability)
                        
                    except json.JSONDecodeError as e:
                        logger.warning(f"   ⚠️  Failed to parse JSON on line {i+1}: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"❌ Error parsing Nuclei results: {e}")
        
        logger.info(f"✅ Parsing completed. Total vulnerabilities: {len(vulnerabilities)}")
        return vulnerabilities
    
    def _map_nuclei_category(self, tags: List[str]) -> str:
        """Map Nuclei tags to vulnerability categories"""
        tag_mapping = {
            'sql-injection': 'sql_injection',
            'xss': 'xss',
            'ssrf': 'ssrf',
            'rce': 'rce',
            'lfi': 'lfi',
            'xxe': 'xxe',
            'auth-bypass': 'authentication',
            'auth': 'authentication',
            'authorization': 'authorization',
            'cors': 'cors',
            'open-redirect': 'open_redirect',
            'ssrf': 'ssrf',
            'sqli': 'sql_injection',
            'nosql': 'nosql_injection',
            'graphql': 'graphql',
            'jwt': 'jwt',
            'oauth': 'oauth',
            'api': 'api_security'
        }
        
        for tag in tags:
            if tag.lower() in tag_mapping:
                return tag_mapping[tag.lower()]
        
        return 'other'
    
    def _check_ssrfmap_availability(self) -> bool:
        """Check if SSRFMap is available and working"""
        try:
            if not self.ssrfmap_path or not os.path.exists(self.ssrfmap_path):
                logger.warning("⚠️  SSRFMap path not configured or does not exist")
                return False
            
            # Test SSRFMap availability
            result = subprocess.run(
                [self.ssrfmap_path, '--help'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"⚠️  SSRFMap availability check failed: {e}")
            return False
    
    def _check_xsstrike_availability(self) -> bool:
        """Check if XSStrike is available and working"""
        try:
            if not self.xsstrike_path or not os.path.exists(self.xsstrike_path):
                logger.warning("⚠️  XSStrike path not configured or does not exist")
                return False
            
            # Test XSStrike availability
            result = subprocess.run(
                [self.xsstrike_path, '--help'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"⚠️  XSStrike availability check failed: {e}")
            return False

    def _verify_url_in_context(self, context_name: str, target_url: str) -> bool:
        """Verify that the target URL is included in the ZAP context"""
        try:
            # Get context URLs
            context_urls = self._zap_request('context/view/contextUrls', {
                'contextName': context_name
            })
            
            # Handle both old and new ZAP API response formats
            if 'contextUrls' in context_urls:
                # New format (ZAP 2.12+) - URLs are nested
                urls = context_urls['contextUrls'].get('urls', [])
            else:
                # Old format or fallback
                urls = context_urls.get('urls', [])
            
            logger.info(f"Context '{context_name}' contains {len(urls)} URLs")
            
            # Check if our target URL is in the context
            for url in urls:
                if target_url in url or target_url.split('/')[2] in url:
                    logger.info(f"✅ Target URL found in context: {url}")
                    return True
            
            logger.warning(f"⚠️ Target URL not found in context: {target_url}")
            return False
            
        except Exception as e:
            logger.warning(f"Failed to verify URL in context: {e}")
            return False
    
    def test_zap_api_compatibility(self) -> Dict[str, Any]:
        """Test ZAP API compatibility and identify potential issues"""
        compatibility_results = {
            'zap_accessible': False,
            'api_key_valid': False,
            'context_views_working': False,
            'context_actions_working': False,
            'spider_views_working': False,
            'ascan_views_working': False,
            'core_views_working': False,
            'issues': [],
            'recommendations': []
        }
        
        try:
            # Test basic ZAP connectivity
            logger.info("🔍 Testing ZAP API compatibility...")
            
            # Test 1: Basic connectivity
            try:
                basic_info = self._zap_request('core/view/version')
                compatibility_results['zap_accessible'] = True
                logger.info(f"✅ ZAP version: {basic_info.get('version', 'Unknown')}")
            except Exception as e:
                compatibility_results['issues'].append(f"ZAP not accessible: {e}")
                return compatibility_results
            
            # Test 2: API key validation
            try:
                # Try a simple action that requires API key
                self._zap_request('context/action/newContext', {'contextName': 'test_context'})
                compatibility_results['api_key_valid'] = True
                logger.info("✅ API key is valid")
                
                # Clean up test context
                try:
                    self._zap_request('context/action/removeContext', {'contextName': 'test_context'})
                except:
                    pass
            except Exception as e:
                compatibility_results['issues'].append(f"API key validation failed: {e}")
                compatibility_results['recommendations'].append("Check ZAP API key configuration")
            
            # Test 3: Context views
            try:
                contexts = self._zap_request('context/view/contextList')
                if 'contextList' in contexts or 'contextList' in contexts.get('contextList', {}):
                    compatibility_results['context_views_working'] = True
                    logger.info("✅ Context views are working")
                else:
                    compatibility_results['issues'].append("Context views returned unexpected format")
            except Exception as e:
                if 'bad_view' in str(e).lower():
                    compatibility_results['issues'].append("Context views returning 'bad_view' error - ZAP version compatibility issue")
                    compatibility_results['recommendations'].append("Consider upgrading ZAP or using fallback context handling")
                else:
                    compatibility_results['issues'].append(f"Context views failed: {e}")
            
            # Test 4: Context actions
            try:
                self._zap_request('context/action/newContext', {'contextName': 'test_action_context'})
                self._zap_request('context/action/removeContext', {'contextName': 'test_action_context'})
                compatibility_results['context_actions_working'] = True
                logger.info("✅ Context actions are working")
            except Exception as e:
                compatibility_results['issues'].append(f"Context actions failed: {e}")
            
            # Test 5: Spider views
            try:
                spider_status = self._zap_request('spider/view/status')
                if 'spiderStatus' in spider_status or 'status' in spider_status:
                    compatibility_results['spider_views_working'] = True
                    logger.info("✅ Spider views are working")
                else:
                    compatibility_results['issues'].append("Spider views returned unexpected format")
            except Exception as e:
                compatibility_results['issues'].append(f"Spider views failed: {e}")
            
            # Test 6: Active scan views
            try:
                ascan_status = self._zap_request('ascan/view/status')
                if 'ascanStatus' in ascan_status or 'status' in ascan_status:
                    compatibility_results['ascan_views_working'] = True
                    logger.info("✅ Active scan views are working")
                else:
                    compatibility_results['issues'].append("Active scan views returned unexpected format")
            except Exception as e:
                compatibility_results['issues'].append(f"Active scan views failed: {e}")
            
            # Test 7: Core views
            try:
                alerts = self._zap_request('core/view/alerts')
                if 'alerts' in alerts or 'alerts' in alerts.get('alerts', {}):
                    compatibility_results['core_views_working'] = True
                    logger.info("✅ Core views are working")
                else:
                    compatibility_results['issues'].append("Core views returned unexpected format")
            except Exception as e:
                compatibility_results['issues'].append(f"Core views failed: {e}")
            
            # Generate recommendations
            if not compatibility_results['context_views_working']:
                compatibility_results['recommendations'].append("Context views are not working - the scanner will use fallback methods")
            
            if not compatibility_results['spider_views_working']:
                compatibility_results['recommendations'].append("Spider views are not working - scan progress monitoring may be limited")
            
            if not compatibility_results['ascan_views_working']:
                compatibility_results['recommendations'].append("Active scan views are not working - scan progress monitoring may be limited")
            
            logger.info("✅ ZAP API compatibility test completed")
            
        except Exception as e:
            compatibility_results['issues'].append(f"Compatibility test failed: {e}")
            logger.error(f"❌ ZAP API compatibility test failed: {e}")
        
        return compatibility_results

def scan_endpoint_for_vulnerabilities(endpoint: Dict, param_values: Dict, scan_type: str = 'combined') -> Dict:
    """
    Convenience function to scan an endpoint for vulnerabilities
    
    Args:
        endpoint: Endpoint information
        param_values: Parameter values
        scan_type: Type of scan
        
    Returns:
        Scan results
    """
    scanner = SecurityScanner()
    return scanner.scan_endpoint(endpoint, param_values, scan_type)

def test_zap_compatibility() -> Dict[str, Any]:
    """
    Convenience function to test ZAP API compatibility
    
    Returns:
        Compatibility test results
    """
    scanner = SecurityScanner()
    return scanner.test_zap_api_compatibility()
