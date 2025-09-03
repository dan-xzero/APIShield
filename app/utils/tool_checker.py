"""
Tool Status Checker for Security Scanning Tools
"""

import subprocess
import os
import json
import logging
from typing import Dict, List, Any
from app.config import Config

logger = logging.getLogger(__name__)

class ToolChecker:
    """Check status and functionality of security scanning tools"""
    
    def __init__(self):
        self.tools = {
            'zap': {
                'path': Config.ZAP_PATH,
                'api_url': Config.ZAP_API_URL,
                'api_key': Config.ZAP_API_KEY,
                'type': 'daemon'
            },
            'sqlmap': {
                'path': Config.SQLMAP_PATH,
                'type': 'cli'
            },
            'nuclei': {
                'path': Config.NUCLEI_PATH,
                'type': 'cli'
            },
            'xsstrike': {
                'path': Config.XSSTRIKE_PATH,
                'type': 'cli'
            },
            'ssrfmap': {
                'path': Config.SSRFMAP_PATH,
                'type': 'cli'
            }
        }
    
    def check_all_tools(self) -> Dict[str, Any]:
        """Check status of all tools"""
        results = {}
        
        for tool_name, tool_info in self.tools.items():
            logger.info(f"🔍 Checking {tool_name}...")
            results[tool_name] = self._check_tool(tool_name, tool_info)
        
        return results
    
    def _check_tool(self, tool_name: str, tool_info: Dict) -> Dict[str, Any]:
        """Check individual tool status"""
        result = {
            'name': tool_name,
            'status': 'unknown',
            'version': 'unknown',
            'path': tool_info['path'],
            'type': tool_info['type'],
            'details': {}
        }
        
        try:
            if tool_info['type'] == 'daemon':
                result.update(self._check_daemon_tool(tool_name, tool_info))
            elif tool_info['type'] == 'cli':
                result.update(self._check_cli_tool(tool_name, tool_info))
            
        except Exception as e:
            result['status'] = 'error'
            result['details']['error'] = str(e)
            logger.error(f"Error checking {tool_name}: {e}")
        
        return result
    
    def _check_daemon_tool(self, tool_name: str, tool_info: Dict) -> Dict[str, Any]:
        """Check daemon-based tools (like ZAP)"""
        if tool_name == 'zap':
            return self._check_zap_status(tool_info)
        return {'status': 'unknown', 'details': {'error': 'Unknown daemon tool'}}
    
    def _check_cli_tool(self, tool_name: str, tool_info: Dict) -> Dict[str, Any]:
        """Check command-line tools"""
        result = {'status': 'unknown'}
        
        # Check if tool exists
        if not os.path.exists(tool_info['path']):
            result['status'] = 'not_found'
            result['details']['error'] = f"Tool not found at {tool_info['path']}"
            return result
        
        # Check if tool is executable
        if not os.access(tool_info['path'], os.X_OK):
            result['status'] = 'not_executable'
            result['details']['error'] = f"Tool not executable at {tool_info['path']}"
            return result
        
        # Try to get version
        try:
            version_result = subprocess.run(
                [tool_info['path'], '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if version_result.returncode == 0:
                result['status'] = 'working'
                result['version'] = version_result.stdout.strip()
                result['details']['version_output'] = version_result.stdout.strip()
            else:
                result['status'] = 'version_error'
                result['details']['error'] = f"Version check failed: {version_result.stderr}"
                
        except subprocess.TimeoutExpired:
            result['status'] = 'timeout'
            result['details']['error'] = 'Version check timed out'
        except Exception as e:
            result['status'] = 'error'
            result['details']['error'] = f"Version check error: {str(e)}"
        
        return result
    
    def _check_zap_status(self, tool_info: Dict) -> Dict[str, Any]:
        """Check ZAP daemon status"""
        result = {'status': 'unknown'}
        
        try:
            # Check if ZAP process is running
            zap_process = subprocess.run(
                ['pgrep', '-f', 'zap.*daemon'],
                capture_output=True,
                text=True
            )
            
            if zap_process.returncode == 0:
                result['status'] = 'running'
                result['details']['pid'] = zap_process.stdout.strip()
                
                # Test ZAP API
                import requests
                try:
                    api_url = f"{tool_info['api_url']}/JSON/core/view/version"
                    response = requests.get(api_url, timeout=5)
                    
                    if response.status_code == 200:
                        result['details']['api_status'] = 'working'
                        result['details']['api_response'] = response.json()
                    else:
                        result['details']['api_status'] = 'error'
                        result['details']['api_error'] = f"HTTP {response.status_code}"
                        
                except Exception as api_error:
                    result['details']['api_status'] = 'error'
                    result['details']['api_error'] = str(api_error)
                    
            else:
                result['status'] = 'not_running'
                result['details']['error'] = 'ZAP daemon process not found'
                
        except Exception as e:
            result['status'] = 'error'
            result['details']['error'] = str(e)
        
        return result
    
    def test_tool_functionality(self, tool_name: str) -> Dict[str, Any]:
        """Test actual functionality of a tool with a simple test"""
        if tool_name not in self.tools:
            return {'error': f'Unknown tool: {tool_name}'}
        
        tool_info = self.tools[tool_name]
        
        if tool_name == 'sqlmap':
            return self._test_sqlmap(tool_info)
        elif tool_name == 'nuclei':
            return self._test_nuclei(tool_info)
        elif tool_name == 'zap':
            return self._test_zap(tool_info)
        else:
            return {'error': f'Testing not implemented for {tool_name}'}
    
    def _test_sqlmap(self, tool_info: Dict) -> Dict[str, Any]:
        """Test SQLMap with help command"""
        try:
            result = subprocess.run(
                [tool_info['path'], '--help'],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            return {
                'status': 'tested',
                'exit_code': result.returncode,
                'stdout_length': len(result.stdout),
                'stderr_length': len(result.stderr),
                'working': result.returncode == 0
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _test_nuclei(self, tool_info: Dict) -> Dict[str, Any]:
        """Test Nuclei with help command"""
        try:
            result = subprocess.run(
                [tool_info['path'], '--help'],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            return {
                'status': 'tested',
                'exit_code': result.returncode,
                'stdout_length': len(result.stdout),
                'stderr_length': len(result.stderr),
                'working': result.returncode == 0
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _test_zap(self, tool_info: Dict) -> Dict[str, Any]:
        """Test ZAP API functionality"""
        try:
            import requests
            
            # Test basic API call
            api_url = f"{tool_info['api_url']}/JSON/core/view/version"
            response = requests.get(api_url, timeout=5)
            
            return {
                'status': 'tested',
                'api_status_code': response.status_code,
                'api_working': response.status_code == 200,
                'api_response': response.json() if response.status_code == 200 else None
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def get_recommendations(self, tool_status: Dict[str, Any]) -> List[str]:
        """Get recommendations for fixing tool issues"""
        recommendations = []
        
        for tool_name, status in tool_status.items():
            if status['status'] == 'not_found':
                recommendations.append(f"Install {tool_name} at {status['path']}")
            elif status['status'] == 'not_executable':
                recommendations.append(f"Make {tool_name} executable: chmod +x {status['path']}")
            elif status['status'] == 'not_running' and tool_name == 'zap':
                recommendations.append("Start ZAP daemon: /Applications/ZAP.app/Contents/Java/zap.sh -daemon -port 8080")
            elif status['status'] == 'error':
                recommendations.append(f"Check {tool_name} configuration and logs")
        
        return recommendations

def check_tools_status():
    """Convenience function to check all tools"""
    checker = ToolChecker()
    return checker.check_all_tools()

def test_tool(tool_name: str):
    """Convenience function to test a specific tool"""
    checker = ToolChecker()
    return checker.test_tool_functionality(tool_name)
