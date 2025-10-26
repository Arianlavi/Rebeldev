#!/usr/bin/env python3
"""
RebelDev Enterprise VPN Configuration Scanner
============================================

A professional-grade automated VPN configuration management system that:
- Fetches configurations from trusted sources
- Validates and performance-tests each configuration  
- Maintains optimized configuration repositories
- Provides enterprise-level reliability and reporting

Author: Arian Lavi
Version: 3.0.0
License: Proprietary - RebelDev Internal Use
"""

import requests
import base64
import json
import socket
import time
import os
import sys
import logging
from urllib.parse import urlparse, unquote
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib


# =============================================================================
# ENTERPRISE CONFIGURATION MANAGEMENT
# =============================================================================

@dataclass
class ScannerConfig:
    """Centralized configuration management for enterprise settings"""
    
    # Source configuration
    SOURCE_REPOSITORY: str = "Epodonios/v2ray-configs"
    SOURCE_BRANCH: str = "main"
    SOURCE_PATH: str = "Splitted-By-Protocol"
    
    # Performance thresholds
    MAX_LATENCY_MS: int = 800
    CONNECTION_TIMEOUT: int = 5
    REQUEST_TIMEOUT: int = 15
    MAX_WORKERS: int = 10
    
    # Output configuration
    OUTPUT_DIRECTORY: str = "RebelLink"
    CONFIG_RETENTION_DAYS: int = 7
    
    # Protocol-specific settings
    DEFAULT_PORTS: Dict[str, int] = None
    
    def __post_init__(self):
        if self.DEFAULT_PORTS is None:
            self.DEFAULT_PORTS = {
                'ss': 8388,
                'trojan': 443,
                'vless': 443,
                'vmess': 443
            }


@dataclass
class VPNConfig:
    """Standardized VPN configuration data structure"""
    protocol: str
    raw_config: str
    host: str
    port: int
    remark: str
    latency: Optional[int] = None
    is_valid: bool = False
    config_hash: str = None
    last_tested: datetime = None
    
    def __post_init__(self):
        if self.config_hash is None:
            self.config_hash = self.generate_hash()
        if self.last_tested is None:
            self.last_tested = datetime.utcnow()
    
    def generate_hash(self) -> str:
        """Generate unique hash for configuration deduplication"""
        content = f"{self.protocol}:{self.host}:{self.port}:{self.remark}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize configuration to dictionary"""
        return {
            'protocol': self.protocol,
            'raw_config': self.raw_config,
            'host': self.host,
            'port': self.port,
            'remark': self.remark,
            'latency': self.latency,
            'is_valid': self.is_valid,
            'config_hash': self.config_hash,
            'last_tested': self.last_tested.isoformat()
        }


# =============================================================================
# ENTERPRISE LOGGING SYSTEM
# =============================================================================

class EnterpriseLogger:
    """Comprehensive logging system for enterprise environments"""
    
    def __init__(self):
        self.logger = logging.getLogger('RebelDevScanner')
        self.setup_logging()
    
    def setup_logging(self):
        """Configure enterprise-grade logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # File handler for audit trail
        file_handler = logging.FileHandler('scanner_audit.log')
        file_handler.setFormatter(
            logging.Formatter('%(asctime)s | %(levelname)-8s | %(module)-15s | %(message)s')
        )
        self.logger.addHandler(file_handler)
    
    def log_operation(self, operation: str, details: str = ""):
        """Log business operations"""
        self.logger.info(f"OPERATION: {operation} | {details}")
    
    def log_security(self, event: str, details: str = ""):
        """Log security-related events"""
        self.logger.warning(f"SECURITY: {event} | {details}")
    
    def log_performance(self, metric: str, value: Any):
        """Log performance metrics"""
        self.logger.info(f"PERFORMANCE: {metric} = {value}")
    
    def log_error(self, error: str, context: str = ""):
        """Log error events with context"""
        self.logger.error(f"ERROR: {error} | Context: {context}")


# =============================================================================
# CORE SCANNER ENGINE
# =============================================================================

class EnterpriseVPNScanner:
    """
    Enterprise-grade VPN configuration scanner with advanced features:
    - Multi-threaded performance testing
    - Configuration deduplication
    - Comprehensive error handling
    - Performance analytics
    - Security validation
    """
    
    def __init__(self, config: ScannerConfig = None):
        self.config = config or ScannerConfig()
        self.logger = EnterpriseLogger()
        self.performance_stats = {
            'start_time': None,
            'total_processed': 0,
            'valid_configs': 0,
            'failed_tests': 0,
            'duplicates_found': 0
        }
        
        # Initialize source URLs
        self.sources = self._initialize_sources()
        
        # Configuration tracking
        self.unique_configs = set()
        self.validated_configs = {}
    
    def _initialize_sources(self) -> Dict[str, str]:
        """Initialize source URLs with enterprise formatting"""
        base_url = f"https://raw.githubusercontent.com/{self.config.SOURCE_REPOSITORY}"
        return {
            'vless': f"{base_url}/{self.config.SOURCE_BRANCH}/{self.config.SOURCE_PATH}/vless.txt",
            'vmess': f"{base_url}/{self.config.SOURCE_BRANCH}/{self.config.SOURCE_PATH}/vmess.txt",
            'ss': f"{base_url}/{self.config.SOURCE_BRANCH}/{self.config.SOURCE_PATH}/ss.txt",
            'trojan': f"{base_url}/{self.config.SOURCE_BRANCH}/{self.config.SOURCE_PATH}/trojan.txt"
        }
    
    def _make_enterprise_request(self, url: str) -> Optional[str]:
        """
        Make enterprise-grade HTTP request with comprehensive error handling
        and security considerations
        """
        try:
            headers = {
                'User-Agent': 'RebelDev-Enterprise-Scanner/3.0.0',
                'Accept': 'text/plain, application/json',
                'X-Request-ID': hashlib.md5(url.encode()).hexdigest()[:16]
            }
            
            response = requests.get(
                url,
                timeout=self.config.REQUEST_TIMEOUT,
                headers=headers,
                allow_redirects=True
            )
            
            response.raise_for_status()
            
            # Security validation
            if len(response.content) > 10 * 1024 * 1024:  # 10MB limit
                self.logger.log_security("Oversized response", f"URL: {url}")
                return None
                
            self.logger.log_performance("Request successful", f"URL: {url}")
            return response.text
            
        except requests.exceptions.Timeout:
            self.logger.log_error("Request timeout", f"URL: {url}")
            return None
        except requests.exceptions.HTTPError as e:
            self.logger.log_error(f"HTTP error: {e.response.status_code}", f"URL: {url}")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.log_error(f"Request exception: {str(e)}", f"URL: {url}")
            return None
        except Exception as e:
            self.logger.log_error(f"Unexpected request error: {str(e)}", f"URL: {url}")
            return None
    
    def _safe_base64_decode(self, encoded_data: str) -> Optional[str]:
        """
        Safely decode base64 with comprehensive error handling
        and security validation
        """
        try:
            # Remove URL-safe encoding if present
            encoded_data = encoded_data.replace('-', '+').replace('_', '/')
            
            # Add padding if necessary
            padding = 4 - len(encoded_data) % 4
            if padding != 4:
                encoded_data += '=' * padding
            
            decoded = base64.b64decode(encoded_data).decode('utf-8')
            return decoded
            
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            self.logger.log_error(f"Base64 decode failed", f"Error: {str(e)}")
            return None
        except Exception as e:
            self.logger.log_error(f"Unexpected decode error", f"Error: {str(e)}")
            return None
    
    def _parse_vmess_configuration(self, raw_config: str) -> Optional[VPNConfig]:
        """Parse VMESS configuration with enterprise-grade validation"""
        try:
            if not raw_config.startswith('vmess://'):
                return None
            
            encoded_data = raw_config[8:]
            decoded_json = self._safe_base64_decode(encoded_data)
            if not decoded_json:
                return None
            
            config_data = json.loads(decoded_json)
            
            # Validate required fields
            required_fields = ['add', 'port']
            if not all(field in config_data for field in required_fields):
                self.logger.log_error("Missing required VMESS fields", f"Config: {raw_config[:50]}...")
                return None
            
            host = config_data['add']
            port = int(config_data['port'])
            remark = config_data.get('ps', 'Unnamed VMESS')
            
            return VPNConfig(
                protocol='vmess',
                raw_config=raw_config,
                host=host,
                port=port,
                remark=remark
            )
            
        except json.JSONDecodeError as e:
            self.logger.log_error("VMESS JSON decode failed", f"Error: {str(e)}")
            return None
        except (KeyError, ValueError, TypeError) as e:
            self.logger.log_error("VMESS config validation failed", f"Error: {str(e)}")
            return None
    
    def _parse_standard_configuration(self, raw_config: str, protocol: str) -> Optional[VPNConfig]:
        """Parse standard URL-based configurations (VLESS, Trojan, Shadowsocks)"""
        try:
            parsed = urlparse(raw_config)
            
            if not parsed.hostname:
                self.logger.log_error("Missing hostname", f"Config: {raw_config[:50]}...")
                return None
            
            host = parsed.hostname
            port = parsed.port or self.config.DEFAULT_PORTS.get(protocol, 443)
            remark = unquote(parsed.fragment) if parsed.fragment else f'Unnamed {protocol.upper()}'
            
            return VPNConfig(
                protocol=protocol,
                raw_config=raw_config,
                host=host,
                port=port,
                remark=remark
            )
            
        except Exception as e:
            self.logger.log_error(f"{protocol.upper()} parse failed", f"Error: {str(e)}")
            return None
    
    def _performance_test_configuration(self, config: VPNConfig) -> VPNConfig:
        """
        Perform comprehensive performance testing on VPN configuration
        with enterprise-grade metrics
        """
        try:
            start_time = time.time()
            
            # Create socket with enterprise timeout settings
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.CONNECTION_TIMEOUT)
            
            # Attempt connection
            sock.connect((config.host, config.port))
            sock.close()
            
            end_time = time.time()
            latency = int((end_time - start_time) * 1000)
            
            # Validate against performance thresholds
            if latency <= self.config.MAX_LATENCY_MS:
                config.latency = latency
                config.is_valid = True
                self.logger.log_performance("Connection test passed", 
                                          f"{config.host}:{config.port} - {latency}ms")
            else:
                config.is_valid = False
                self.logger.log_performance("Connection test failed - High latency",
                                          f"{config.host}:{config.port} - {latency}ms")
            
        except socket.timeout:
            config.is_valid = False
            self.logger.log_performance("Connection test failed - Timeout",
                                      f"{config.host}:{config.port}")
        except (socket.gaierror, ConnectionRefusedError, OSError) as e:
            config.is_valid = False
            self.logger.log_performance("Connection test failed - Network error",
                                      f"{config.host}:{config.port} - {str(e)}")
        except Exception as e:
            config.is_valid = False
            self.logger.log_error("Unexpected connection error",
                                f"{config.host}:{config.port} - {str(e)}")
        
        config.last_tested = datetime.utcnow()
        return config
    
    def _process_configuration_batch(self, protocol: str, raw_configs: List[str]) -> List[VPNConfig]:
        """
        Process batch of configurations with multi-threading and deduplication
        """
        validated_configs = []
        
        with ThreadPoolExecutor(max_workers=self.config.MAX_WORKERS) as executor:
            # Parse configurations
            future_to_config = {}
            for raw_config in raw_configs:
                if not raw_config or raw_config.startswith(('#', '//')):
                    continue
                
                future = executor.submit(self._parse_single_configuration, protocol, raw_config)
                future_to_config[future] = raw_config
            
            # Collect parsed configurations
            parsed_configs = []
            for future in as_completed(future_to_config):
                try:
                    config = future.result()
                    if config and config.config_hash not in self.unique_configs:
                        parsed_configs.append(config)
                        self.unique_configs.add(config.config_hash)
                    elif config:
                        self.performance_stats['duplicates_found'] += 1
                except Exception as e:
                    raw_config = future_to_config[future]
                    self.logger.log_error("Configuration parsing failed",
                                        f"Config: {raw_config[:50]}... - Error: {str(e)}")
        
            # Performance test valid configurations
            future_to_test = {
                executor.submit(self._performance_test_configuration, config): config
                for config in parsed_configs
            }
            
            for future in as_completed(future_to_test):
                try:
                    tested_config = future.result()
                    if tested_config.is_valid:
                        validated_configs.append(tested_config)
                        self.performance_stats['valid_configs'] += 1
                    else:
                        self.performance_stats['failed_tests'] += 1
                except Exception as e:
                    config = future_to_test[future]
                    self.logger.log_error("Performance testing failed",
                                        f"Config: {config.raw_config[:50]}... - Error: {str(e)}")
        
        return validated_configs
    
    def _parse_single_configuration(self, protocol: str, raw_config: str) -> Optional[VPNConfig]:
        """Parse single configuration with protocol-specific handler"""
        try:
            if protocol == 'vmess':
                return self._parse_vmess_configuration(raw_config)
            else:
                return self._parse_standard_configuration(raw_config, protocol)
        except Exception as e:
            self.logger.log_error(f"{protocol.upper()} parse exception",
                                f"Config: {raw_config[:50]}... - Error: {str(e)}")
            return None
    
    def scan_protocol(self, protocol: str) -> List[VPNConfig]:
        """
        Execute complete scanning pipeline for specific protocol
        with enterprise-grade error handling
        """
        self.logger.log_operation("Protocol scan initiated", f"Protocol: {protocol.upper()}")
        
        source_url = self.sources.get(protocol)
        if not source_url:
            self.logger.log_error("Invalid protocol specified", f"Protocol: {protocol}")
            return []
        
        # Fetch raw configurations
        raw_content = self._make_enterprise_request(source_url)
        if not raw_content:
            self.logger.log_error("Failed to fetch configurations", f"Protocol: {protocol}")
            return []
        
        # Parse and filter configurations
        raw_configs = [
            line.strip() for line in raw_content.split('\n')
            if line.strip() and not line.startswith(('#', '//'))
        ]
        
        self.performance_stats['total_processed'] += len(raw_configs)
        self.logger.log_performance("Configurations fetched",
                                  f"Protocol: {protocol} - Count: {len(raw_configs)}")
        
        # Process configurations
        validated_configs = self._process_configuration_batch(protocol, raw_configs)
        
        # Sort by performance
        validated_configs.sort(key=lambda x: x.latency or 9999)
        
        self.logger.log_operation("Protocol scan completed",
                                f"Protocol: {protocol} - Valid: {len(validated_configs)}")
        
        return validated_configs
    
    def generate_enterprise_report(self) -> Dict[str, Any]:
        """Generate comprehensive enterprise performance report"""
        duration = datetime.utcnow() - self.performance_stats['start_time']
        
        report = {
            'scan_timestamp': datetime.utcnow().isoformat(),
            'duration_seconds': round(duration.total_seconds(), 2),
            'performance_metrics': {
                'total_configurations_processed': self.performance_stats['total_processed'],
                'valid_configurations_found': self.performance_stats['valid_configs'],
                'duplicate_configurations_removed': self.performance_stats['duplicates_found'],
                'failed_connection_tests': self.performance_stats['failed_tests'],
                'success_rate': round(
                    (self.performance_stats['valid_configs'] / max(self.performance_stats['total_processed'], 1)) * 100, 2
                )
            },
            'protocol_summary': {
                protocol: len(configs) for protocol, configs in self.validated_configs.items()
            },
            'system_metrics': {
                'unique_configurations_tracked': len(self.unique_configs),
                'output_directory': self.config.OUTPUT_DIRECTORY
            }
        }
        
        return report
    
    def save_configurations(self):
        """Save validated configurations with enterprise formatting and metadata"""
        try:
            os.makedirs(self.config.OUTPUT_DIRECTORY, exist_ok=True)
            timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            
            for protocol, configs in self.validated_configs.items():
                if not configs:
                    continue
                
                # Generate primary protocol file
                filename = f"{self.config.OUTPUT_DIRECTORY}/{protocol}.txt"
                self._write_configuration_file(filename, configs, timestamp, protocol)
                
                # Generate SSR file for shadowsocks
                if protocol == 'ss':
                    ssr_filename = f"{self.config.OUTPUT_DIRECTORY}/ssr.txt"
                    self._write_configuration_file(ssr_filename, configs, timestamp, 'ssr')
            
            self.logger.log_operation("Configurations saved", 
                                    f"Directory: {self.config.OUTPUT_DIRECTORY}")
            
        except Exception as e:
            self.logger.log_error("Failed to save configurations", f"Error: {str(e)}")
            raise
    
    def _write_configuration_file(self, filename: str, configs: List[VPNConfig], 
                                timestamp: str, protocol: str):
        """Write configuration file with enterprise formatting"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # Enterprise header with comprehensive metadata
                f.write("# =============================================================================\n")
                f.write("# RebelDev Enterprise VPN Configurations\n")
                f.write("# =============================================================================\n")
                f.write(f"# Protocol: {protocol.upper()}\n")
                f.write(f"# Generated: {timestamp}\n")
                f.write(f"# Total Configurations: {len(configs)}\n")
                f.write(f"# Average Latency: {sum(c.latency for c in configs if c.latency) // len(configs)}ms\n")
                f.write(f"# Source: {self.config.SOURCE_REPOSITORY}\n")
                f.write(f"# Scanner Version: 3.0.0\n")
                f.write("# Security Level: ENTERPRISE_GRADE\n")
                f.write("# =============================================================================\n\n")
                
                # Write configurations
                for config in configs:
                    f.write(f"{config.raw_config}\n")
            
            self.logger.log_performance("Configuration file written", f"File: {filename}")
            
        except IOError as e:
            self.logger.log_error("File write operation failed", f"File: {filename} - Error: {str(e)}")
            raise
    
    def execute_scan(self) -> bool:
        """
        Execute complete enterprise scanning pipeline
        Returns: Boolean indicating overall success
        """
        try:
            self.performance_stats['start_time'] = datetime.utcnow()
            self.logger.log_operation("Enterprise scan pipeline initiated", "Status: STARTED")
            
            # Scan all protocols
            for protocol in self.sources.keys():
                try:
                    configs = self.scan_protocol(protocol)
                    if configs:
                        self.validated_configs[protocol] = configs
                except Exception as e:
                    self.logger.log_error(f"Protocol scan failed: {protocol}", f"Error: {str(e)}")
                    continue
            
            # Save results
            if any(self.validated_configs.values()):
                self.save_configurations()
                
                # Generate final report
                report = self.generate_enterprise_report()
                self._log_enterprise_report(report)
                
                self.logger.log_operation("Enterprise scan pipeline completed", "Status: SUCCESS")
                return True
            else:
                self.logger.log_operation("Enterprise scan pipeline completed", "Status: NO_VALID_CONFIGS")
                return False
                
        except Exception as e:
            self.logger.log_error("Enterprise scan pipeline failed", f"Error: {str(e)}")
            return False
    
    def _log_enterprise_report(self, report: Dict[str, Any]):
        """Log comprehensive enterprise report"""
        self.logger.log_operation("ENTERPRISE_SCAN_REPORT", "BEGIN")
        
        for section, data in report.items():
            if isinstance(data, dict):
                for key, value in data.items():
                    self.logger.log_performance(f"{section}.{key}", value)
            else:
                self.logger.log_performance(section, data)
        
        self.logger.log_operation("ENTERPRISE_SCAN_REPORT", "END")


# =============================================================================
# ENTERPRISE EXECUTION HANDLER
# =============================================================================

class EnterpriseExecutionManager:
    """
    Enterprise-grade execution manager with comprehensive
    error handling and system integration
    """
    
    def __init__(self):
        self.scanner = EnterpriseVPNScanner()
        self.logger = self.scanner.logger
    
    def execute_with_enterprise_handling(self) -> int:
        """
        Execute scanner with enterprise-grade error handling
        and proper exit codes for CI/CD systems
        """
        try:
            self.logger.log_operation("Enterprise execution manager", "INITIALIZED")
            
            success = self.scanner.execute_scan()
            
            if success:
                self.logger.log_operation("Enterprise execution", "COMPLETED_SUCCESS")
                return 0  # Success exit code
            else:
                self.logger.log_operation("Enterprise execution", "COMPLETED_NO_CONFIGS")
                return 1  # No valid configurations
            
        except KeyboardInterrupt:
            self.logger.log_operation("Enterprise execution", "INTERRUPTED_BY_USER")
            return 130  # Standard interrupt code
            
        except Exception as e:
            self.logger.log_error("Enterprise execution", f"CRITICAL_FAILURE: {str(e)}")
            return 2  # Critical failure code


# =============================================================================
# ENTERPRISE ENTRY POINT
# =============================================================================

def main():
    """
    Enterprise entry point with comprehensive system integration
    and professional error handling
    """
    execution_manager = EnterpriseExecutionManager()
    exit_code = execution_manager.execute_with_enterprise_handling()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()