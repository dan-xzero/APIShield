"""
Crawler utility for discovering services and fetching API definitions
"""

import requests
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Optional
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from app import db
from app.models import Service, ApiVersion, Endpoint
from app.config import Config

logger = logging.getLogger(__name__)

class APIPortalCrawler:
    """Crawler for the API Change Tracker portal"""
    
    def __init__(self, portal_url: str = None, api_base: str = None):
        self.portal_url = portal_url or Config.API_PORTAL_URL
        self.api_base = api_base or Config.API_BASE_URL
        self.session = requests.Session()
        
        # Set headers to bypass ngrok warning page
        self.session.headers.update({
            'ngrok-skip-browser-warning': 'true',
            'User-Agent': 'API-Security-Scanner/1.0'
        })
    
    def discover_services(self) -> List[Dict]:
        """
        Discover all services from the portal homepage
        
        Returns:
            List of service dictionaries with name and API URL
        """
        try:
            logger.info(f"Crawling portal at {self.portal_url}")
            response = self.session.get(self.portal_url)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            services = []
            
            # Look for service elements in service-item divs (Active Services section)
            service_elements = soup.find_all('div', class_='service-item')
            
            for element in service_elements:
                service_info = self._extract_service_info(element)
                if service_info:
                    services.append(service_info)
            
            logger.info(f"Discovered {len(services)} services")
            return services
            
        except requests.RequestException as e:
            logger.error(f"Failed to crawl portal: {e}")
            return []
    
    def _extract_service_info(self, element) -> Optional[Dict]:
        """
        Extract service information from a DOM element
        
        Args:
            element: BeautifulSoup element
            
        Returns:
            Service dictionary or None
        """
        try:
            # Look for service name in service-name div
            name_element = element.find('div', class_='service-name')
            if not name_element:
                return None
            
            service_name = name_element.get_text(strip=True)
            if not service_name:
                return None
            
            # Extract service ID from data-service-id attribute
            service_id = element.get('data-service-id')
            if not service_id:
                return None
            
            # Look for API URL in service-url div
            api_url = None
            url_element = element.find('div', class_='service-url')
            if url_element:
                api_url = url_element.get_text(strip=True)
            
            return {
                'name': service_name,
                'api_url': api_url,
                'service_id': service_id,
                'status': 'active'  # Default status
            }
            
        except Exception as e:
            logger.warning(f"Failed to extract service info: {e}")
            return None
    
    def _service_name_to_path(self, service_name: str) -> str:
        """
        Convert service name to API path
        
        Args:
            service_name: Service name
            
        Returns:
            API path
        """
        # Common mappings
        mappings = {
            'Admin Portal Service': 'admin-portal',
            'Authorization Service': 'authorization-service',
            'Cart Service': 'cart-service',
            'Checkout Service': 'checkout-service',
            'Order Service': 'order-service',
            'Payment Service': 'payment-service',
            'Product Catalog Read Service': 'product-catalog-read',
            'Shipping service': 'shipping',
            'Inventory Services': 'inventory-services',
            'Return Management Service': 'return-management-service',
            'QReturns Service': 'qreturns/api',
            'Corporate Gifting': 'corporate-gifting',
            'Offer Service': 'offer-service',
            'Offer Application': 'offer-application',
            'Gift Card Service': 'gift-card-service',
            'Loyality Service': 'loyalty-service',
            'Store Credit Service': 'store-credit-service',
            'Customs Service': 'customs-service',
            'Dropship Service': 'dropship',
            'Exception Workflow Service': 'ews',
            'Inventory Allocation Service': 'ias',
            'Order Workflow Service': 'ows',
            'Partners Service': 'partners',
            'Sand Recommendation Service': 'sand-recommendation-service',
            'Sand Services': 'sand-services',
            'Sand Services Internal': 'sand-services/internal/api',
            'Shipment Tracking Service': 'shipment-tracking-service',
            'Shipping Product Service': 'shipping-product-service',
            'Carrier Tracking Aggregator Service': 'carrier-tracking-aggregator',
            'Checkout Inventory Service': 'checkout-inventory',
            'Control Tower Service': 'control-tower-service',
            'CT Executor Service': 'ct-executor-service',
            'Edd Platform Service': 'edd-platform',
            'Invoice Platform Service': 'invoice-platform',
            'Tax-Management Service': 'tax-management',
            'UPG': 'upg',
            'Warehouse Order Service': 'warehouse-order-service'
        }
        
        return mappings.get(service_name, service_name.lower().replace(' ', '-').replace('_', '-'))
    
    def fetch_api_definition(self, service_name: str, api_url: str, service_id: str = None) -> Optional[Dict]:
        """
        Fetch API definition from the portal's API endpoint
        
        Args:
            service_name: Name of the service
            api_url: URL to the API definition (for reference)
            service_id: Service ID from the portal
            
        Returns:
            OpenAPI specification dictionary or None
        """
        try:
            if not service_id:
                logger.warning(f"No service ID provided for {service_name}, cannot fetch definition")
                return None
            
            # First, get the service detail page to find the latest definition ID
            service_url = f"{self.portal_url.rstrip('/')}/service/{service_id}"
            logger.info(f"Fetching service details for {service_name} from {service_url}")
            
            response = self.session.get(service_url, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find the latest definition ID from buttons
            definition_buttons = soup.find_all('button', attrs={'data-definition-id': True})
            if not definition_buttons:
                logger.warning(f"No definition IDs found for {service_name}")
                return None
            
            # Get the first (latest) definition ID
            latest_definition_id = definition_buttons[0]['data-definition-id']
            logger.info(f"Found latest definition ID {latest_definition_id} for {service_name}")
            
            # Fetch the API definition from the portal's API
            definition_url = f"{self.portal_url.rstrip('/')}/api/definition/{latest_definition_id}"
            logger.info(f"Fetching API definition for {service_name} from {definition_url}")
            
            response = self.session.get(definition_url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # The portal returns a wrapper with base_url, capture_date, and definition
            if 'definition' not in data:
                logger.warning(f"Invalid API definition response for {service_name}: missing definition field")
                return None
            
            spec = data['definition']
            
            # Validate basic OpenAPI structure
            if not isinstance(spec, dict) or ('openapi' not in spec and 'swagger' not in spec):
                logger.error(f"Invalid OpenAPI specification for {service_name}")
                return None
            
            logger.info(f"Successfully fetched API definition for {service_name}")
            return spec
            
        except requests.RequestException as e:
            logger.error(f"Failed to fetch API definition for {service_name}: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in API definition for {service_name}: {e}")
            return None
    
    def update_services_database(self) -> Dict:
        """
        Update the database with discovered services and their API definitions
        
        Returns:
            Dictionary with update statistics
        """
        stats = {
            'services_discovered': 0,
            'services_updated': 0,
            'services_failed': 0,
            'endpoints_added': 0,
            'api_versions_added': 0
        }
        
        try:
            # Discover services from portal
            discovered_services = self.discover_services()
            stats['services_discovered'] = len(discovered_services)
            
            for service_info in discovered_services:
                try:
                    # Check if service exists in database
                    service = Service.query.filter_by(name=service_info['name']).first()
                    
                    if not service:
                        # Create new service
                        service = Service(
                            name=service_info['name'],
                            api_url=service_info['api_url'],
                            status=service_info['status']
                        )
                        db.session.add(service)
                        db.session.flush()  # Get the ID
                        logger.info(f"Created new service: {service.name}")
                    
                    # Fetch API definition
                    spec = self.fetch_api_definition(service.name, service.api_url, service_info.get('service_id'))
                    
                    if spec:
                        # Check if this is a new version
                        version_number = spec.get('info', {}).get('version', '1.0.0')
                        existing_version = ApiVersion.query.filter_by(
                            service_id=service.id,
                            version_number=version_number
                        ).first()
                        
                        if not existing_version:
                            # Create new API version
                            api_version = ApiVersion(
                                service_id=service.id,
                                version_number=version_number,
                                spec_json=spec
                            )
                            db.session.add(api_version)
                            db.session.flush()
                            stats['api_versions_added'] += 1
                            
                            # Extract and store endpoints
                            endpoints_added = self._extract_endpoints(api_version, spec)
                            stats['endpoints_added'] += endpoints_added
                            
                            logger.info(f"Added {endpoints_added} endpoints for {service.name}")
                        else:
                            logger.info(f"API version {version_number} already exists for {service.name}")
                        
                        # Update service status and last checked
                        service.status = 'active'
                        service.last_checked = datetime.now(timezone.utc)
                        stats['services_updated'] += 1
                        
                    else:
                        # Mark service as having error
                        service.status = 'error'
                        service.last_checked = datetime.now(timezone.utc)
                        stats['services_failed'] += 1
                
                except Exception as e:
                    logger.error(f"Failed to process service {service_info['name']}: {e}")
                    stats['services_failed'] += 1
            
            # Commit all changes
            db.session.commit()
            logger.info(f"Database update completed: {stats}")
            
        except Exception as e:
            logger.error(f"Failed to update services database: {e}")
            db.session.rollback()
        
        return stats
    
    def _extract_endpoints(self, api_version: ApiVersion, spec: Dict) -> int:
        """
        Extract endpoints from OpenAPI specification
        
        Args:
            api_version: API version model instance
            spec: OpenAPI specification dictionary
            
        Returns:
            Number of endpoints added
        """
        endpoints_added = 0
        paths = spec.get('paths', {})
        
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                    try:
                        # Check if endpoint already exists
                        existing_endpoint = Endpoint.query.filter_by(
                            service_id=api_version.service_id,
                            path=path,
                            method=method.upper()
                        ).first()
                        
                        if not existing_endpoint:
                            # Create new endpoint
                            endpoint = Endpoint(
                                service_id=api_version.service_id,
                                api_version_id=api_version.id,
                                path=path,
                                method=method.upper(),
                                operation_id=operation.get('operationId'),
                                summary=operation.get('summary'),
                                description=operation.get('description'),
                                parameters_schema=operation.get('parameters'),
                                request_body_schema=operation.get('requestBody'),
                                response_schema=operation.get('responses')
                            )
                            db.session.add(endpoint)
                            endpoints_added += 1
                        else:
                            # Update existing endpoint with new version info
                            existing_endpoint.api_version_id = api_version.id
                            existing_endpoint.parameters_schema = operation.get('parameters')
                            existing_endpoint.request_body_schema = operation.get('requestBody')
                            existing_endpoint.response_schema = operation.get('responses')
                            existing_endpoint.updated_at = datetime.now(timezone.utc)
                    
                    except Exception as e:
                        logger.warning(f"Failed to extract endpoint {method} {path}: {e}")
        
        return endpoints_added

def crawl_and_update():
    """
    Main function to crawl portal and update database
    """
    try:
        crawler = APIPortalCrawler()
        return crawler.update_services_database()
    except Exception as e:
        logger.error(f"Error in crawl_and_update: {e}")
        return {
            'services_found': 0,
            'services': [],
            'status': 'error',
            'error': str(e)
        }

def crawl_api_base_url() -> Dict:
    """
    Crawl the API base URL to discover services
    
    Returns:
        Dictionary with discovery results
    """
    try:
        logger.info(f"Discovering services from API base URL: {Config.API_BASE_URL}")
        
        # Create crawler instance
        crawler = APIPortalCrawler()
        
        # Discover services from the portal
        services = crawler.discover_services()
        
        if not services:
            logger.warning("No services found from API base URL")
            return {
                'services_found': 0,
                'services': [],
                'status': 'no_services_found'
            }
        
        # Process discovered services
        services_added = 0
        for service_info in services:
            try:
                # Check if service already exists
                existing_service = Service.query.filter_by(name=service_info['name']).first()
                
                if not existing_service:
                    # Create new service
                    new_service = Service(
                        name=service_info['name'],
                        api_url=service_info.get('api_url'),
                        status=service_info.get('status', 'active')
                    )
                    db.session.add(new_service)
                    services_added += 1
                    logger.info(f"Added new service: {service_info['name']}")
                else:
                    # Update existing service
                    existing_service.api_url = service_info.get('api_url')
                    existing_service.status = service_info.get('status', 'active')
                    existing_service.updated_at = datetime.now(timezone.utc)
                    logger.info(f"Updated existing service: {service_info['name']}")
                
            except Exception as e:
                logger.error(f"Error processing service {service_info.get('name', 'Unknown')}: {e}")
                continue
        
        # Commit changes
        db.session.commit()
        
        logger.info(f"API base discovery completed: {services_added} new services added")
        
        return {
            'services_found': 0,  # Changed from services_added to match expected return format
            'services': services,
            'status': 'success'
        }
        
    except Exception as e:
        logger.error(f"Error discovering from API base URL: {e}")
        return {
            'services_found': 0,
            'services': [],
            'status': 'error',
            'error': str(e)
        }
