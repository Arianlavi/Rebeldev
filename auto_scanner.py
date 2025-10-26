#!/usr/bin/env python3
"""
RebelDev Enterprise VPN Configuration Scanner
============================================

Enhanced version with:
- Base64 configuration decoding
- Comprehensive ping and relay delay testing
- Multi-protocol support with detailed analytics
- Automated hourly execution

Author: Arian Lavi
Version: 4.0.0
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
import subprocess
import asyncio
import aiohttp
from urllib.parse import urlparse, unquote, parse_qs
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import re


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
# ENHANCED CONFIGURATION MANAGEMENT
# =============================================================================

@dataclass
class ScannerConfig:
    """Enhanced configuration management with performance testing"""
    
    # Source configuration
    SOURCE_REPOSITORY: str = "Epodonios/v2ray-configs"
    SOURCE_BRANCH: str = "main"
    SOURCE_PATH: str = "Splitted-By-Protocol"
    
    # Performance thresholds
    MAX_LATENCY_MS: int = 800
    MAX_JITTER_MS: int = 100
    PACKET_LOSS_THRESHOLD: float = 0.1
    CONNECTION_TIMEOUT: int = 5
    REQUEST_TIMEOUT: int = 15
    MAX_WORKERS: int = 15
    PING_COUNT: int = 3
    
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
                'vmess': 443,
                'ssr': 8388
            }


@dataclass
class VPNConfig:
    """Enhanced VPN configuration with performance metrics"""
    protocol: str
    raw_config: str
    decoded_config: Dict[str, Any]
    host: str
    port: int
    remark: str
    latency: Optional[int] = None
    jitter: Optional[int] = None
    packet_loss: Optional[float] = None
    relay_delay: Optional[int] = None
    is_valid: bool = False
    config_hash: str = None
    last_tested: datetime = None
    performance_score: float = 0.0
    
    def __post_init__(self):
        if self.config_hash is None:
            self.config_hash = self.generate_hash()
        if self.last_tested is None:
            self.last_tested = datetime.utcnow()
    
    def generate_hash(self) -> str:
        """Generate unique hash for configuration deduplication"""
        content = f"{self.protocol}:{self.host}:{self.port}:{self.remark}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def calculate_performance_score(self) -> float:
        """Calculate comprehensive performance score"""
        if not all([self.latency, self.jitter, self.packet_loss is not None]):
            return 0.0
        
        # Normalize metrics (lower is better)
        latency_score = max(0, 100 - (self.latency / 10))
        jitter_score = max(0, 100 - (self.jitter / 2))
        packet_loss_score = max(0, 100 - (self.packet_loss * 1000))
        
        # Weighted average
        self.performance_score = (
            latency_score * 0.5 + 
            jitter_score * 0.3 + 
            packet_loss_score * 0.2
        )
        
        return self.performance_score
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize configuration to dictionary"""
        return {
            'protocol': self.protocol,
            'raw_config': self.raw_config,
            'decoded_config': self.decoded_config,
            'host': self.host,
            'port': self.port,
            'remark': self.remark,
            'latency': self.latency,
            'jitter': self.jitter,
            'packet_loss': self.packet_loss,
            'relay_delay': self.relay_delay,
            'is_valid': self.is_valid,
            'config_hash': self.config_hash,
            'last_tested': self.last_tested.isoformat(),
            'performance_score': self.performance_score
        }


# =============================================================================
# ENHANCED PERFORMANCE TESTING ENGINE
# =============================================================================

class PerformanceTester:
    """Comprehensive performance testing with ping and relay analysis"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = EnterpriseLogger()
    
    async def test_ping_performance(self, host: str) -> Tuple[Optional[int], Optional[int], Optional[float]]:
        """
        Perform comprehensive ping testing with latency, jitter, and packet loss
        """
        try:
            if sys.platform == "win32":
                cmd = ["ping", "-n", str(self.config.PING_COUNT), host]
            else:
                cmd = ["ping", "-c", str(self.config.PING_COUNT), host]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=self.config.CONNECTION_TIMEOUT * 2
            )
            
            return self._parse_ping_output(result.stdout)
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            self.logger.log_error(f"Ping test failed for {host}", f"Error: {str(e)}")
            return None, None, None
    
    def _parse_ping_output(self, output: str) -> Tuple[Optional[int], Optional[int], Optional[float]]:
        """Parse ping command output to extract metrics"""
        try:
            # Extract latency values
            latency_pattern = r'time=([\d.]+)ms'
            latencies = [float(match) for match in re.findall(latency_pattern, output)]
            
            if not latencies:
                return None, None, None
            
            # Calculate average latency
            avg_latency = int(sum(latencies) / len(latencies))
            
            # Calculate jitter (standard deviation of latencies)
            mean = sum(latencies) / len(latencies)
            variance = sum((x - mean) ** 2 for x in latencies) / len(latencies)
            jitter = int(variance ** 0.5)
            
            # Extract packet loss
            loss_pattern = r'(\d+)% packet loss'
            loss_match = re.search(loss_pattern, output)
            packet_loss = float(loss_match.group(1)) / 100 if loss_match else 0.0
            
            return avg_latency, jitter, packet_loss
            
        except Exception as e:
            self.logger.log_error("Ping output parsing failed", f"Error: {str(e)}")
            return None, None, None
    
    async def test_relay_delay(self, host: str, port: int) -> Optional[int]:
        """
        Test relay delay by measuring TCP handshake time
        """
        try:
            start_time = time.time()
            
            # Create socket with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.CONNECTION_TIMEOUT)
            
            # Perform TCP handshake
            sock.connect((host, port))
            sock.close()
            
            end_time = time.time()
            relay_delay = int((end_time - start_time) * 1000)
            
            return relay_delay
            
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
            self.logger.log_performance("Relay delay test failed", f"{host}:{port} - {str(e)}")
            return None
        except Exception as e:
            self.logger.log_error("Unexpected relay delay error", f"{host}:{port} - {str(e)}")
            return None
    
    async def comprehensive_performance_test(self, config: VPNConfig) -> VPNConfig:
        """
        Perform comprehensive performance testing on VPN configuration
        """
        try:
            # Test ping performance
            latency, jitter, packet_loss = await self.test_ping_performance(config.host)
            
            if latency:
                config.latency = latency
                config.jitter = jitter
                config.packet_loss = packet_loss
                
                # Test relay delay only if ping is successful
                relay_delay = await self.test_relay_delay(config.host, config.port)
                config.relay_delay = relay_delay
                
                # Calculate performance score
                config.calculate_performance_score()
                
                # Validate against thresholds
                if (latency <= self.config.MAX_LATENCY_MS and 
                    (not jitter or jitter <= self.config.MAX_JITTER_MS) and 
                    (not packet_loss or packet_loss <= self.config.PACKET_LOSS_THRESHOLD)):
                    config.is_valid = True
                    
                    self.logger.log_performance(
                        "Performance test passed",
                        f"{config.host}:{config.port} - Latency: {latency}ms, Jitter: {jitter}ms, Loss: {packet_loss:.1%}"
                    )
                else:
                    config.is_valid = False
                    self.logger.log_performance(
                        "Performance test failed - Poor metrics",
                        f"{config.host}:{config.port} - Latency: {latency}ms, Jitter: {jitter}ms, Loss: {packet_loss:.1%}"
                    )
            else:
                config.is_valid = False
                self.logger.log_performance(
                    "Performance test failed - No ping response",
                    f"{config.host}:{config.port}"
                )
            
        except Exception as e:
            config.is_valid = False
            self.logger.log_error(
                "Performance testing failed",
                f"{config.host}:{config.port} - {str(e)}"
            )
        
        config.last_tested = datetime.utcnow()
        return config


# =============================================================================
# ENHANCED CONFIGURATION PARSING
# =============================================================================

class ConfigurationParser:
    """Advanced configuration parsing with comprehensive decoding"""
    
    def __init__(self):
        self.logger = EnterpriseLogger()
    
    def decode_base64_config(self, encoded_data: str) -> Optional[str]:
        """Safely decode base64 with comprehensive error handling"""
        try:
            # Handle URL-safe base64
            encoded_data = encoded_data.replace('-', '+').replace('_', '/')
            
            # Add padding if necessary
            padding = 4 - len(encoded_data) % 4
            if padding != 4:
                encoded_data += '=' * padding
            
            decoded = base64.b64decode(encoded_data).decode('utf-8', errors='ignore')
            return decoded
            
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            self.logger.log_error("Base64 decode failed", f"Error: {str(e)}")
            return None
        except Exception as e:
            self.logger.log_error("Unexpected decode error", f"Error: {str(e)}")
            return None
    
    def parse_vmess_configuration(self, raw_config: str) -> Optional[VPNConfig]:
        """Parse VMESS configuration with comprehensive decoding"""
        try:
            if not raw_config.startswith('vmess://'):
                return None
            
            encoded_data = raw_config[8:]
            decoded_json = self.decode_base64_config(encoded_data)
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
                decoded_config=config_data,
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
    
    def parse_vless_configuration(self, raw_config: str) -> Optional[VPNConfig]:
        """Parse VLESS configuration with comprehensive analysis"""
        try:
            parsed = urlparse(raw_config)
            
            if not parsed.hostname:
                self.logger.log_error("Missing hostname in VLESS", f"Config: {raw_config[:50]}...")
                return None
            
            host = parsed.hostname
            port = parsed.port or 443
            remark = unquote(parsed.fragment) if parsed.fragment else 'Unnamed VLESS'
            
            # Parse query parameters for additional details
            query_params = parse_qs(parsed.query)
            decoded_config = {
                'host': host,
                'port': port,
                'remark': remark,
                'protocol': 'vless',
                'query_params': query_params,
                'network': query_params.get('type', ['tcp'])[0],
                'security': query_params.get('security', ['none'])[0]
            }
            
            return VPNConfig(
                protocol='vless',
                raw_config=raw_config,
                decoded_config=decoded_config,
                host=host,
                port=port,
                remark=remark
            )
            
        except Exception as e:
            self.logger.log_error("VLESS parse failed", f"Error: {str(e)}")
            return None
    
    def parse_shadowsocks_configuration(self, raw_config: str) -> Optional[VPNConfig]:
        """Parse Shadowsocks configuration with comprehensive decoding"""
        try:
            if raw_config.startswith('ss://'):
                # Handle both plain and base64 encoded SS configurations
                config_part = raw_config[5:]
                
                # Check if it's base64 encoded
                if '@' not in config_part:
                    decoded = self.decode_base64_config(config_part)
                    if decoded:
                        config_part = decoded
                
                parsed = urlparse(f"ss://{config_part}")
                host = parsed.hostname
                port = parsed.port or 8388
                remark = unquote(parsed.fragment) if parsed.fragment else 'Unnamed Shadowsocks'
                
                # Parse authentication
                auth_part = parsed.username
                if auth_part and ':' in auth_part:
                    method, password = auth_part.split(':', 1)
                else:
                    method, password = 'chacha20-ietf-poly1305', 'unknown'
                
                decoded_config = {
                    'host': host,
                    'port': port,
                    'remark': remark,
                    'method': method,
                    'password': password,
                    'protocol': 'ss'
                }
                
                return VPNConfig(
                    protocol='ss',
                    raw_config=raw_config,
                    decoded_config=decoded_config,
                    host=host,
                    port=port,
                    remark=remark
                )
            
            return None
            
        except Exception as e:
            self.logger.log_error("Shadowsocks parse failed", f"Error: {str(e)}")
            return None
    
    def parse_trojan_configuration(self, raw_config: str) -> Optional[VPNConfig]:
        """Parse Trojan configuration with comprehensive analysis"""
        try:
            parsed = urlparse(raw_config)
            
            if not parsed.hostname:
                self.logger.log_error("Missing hostname in Trojan", f"Config: {raw_config[:50]}...")
                return None
            
            host = parsed.hostname
            port = parsed.port or 443
            password = parsed.username or 'unknown'
            remark = unquote(parsed.fragment) if parsed.fragment else 'Unnamed Trojan'
            
            # Parse query parameters
            query_params = parse_qs(parsed.query)
            decoded_config = {
                'host': host,
                'port': port,
                'password': password,
                'remark': remark,
                'protocol': 'trojan',
                'query_params': query_params,
                'security': query_params.get('security', ['tls'])[0]
            }
            
            return VPNConfig(
                protocol='trojan',
                raw_config=raw_config,
                decoded_config=decoded_config,
                host=host,
                port=port,
                remark=remark
            )
            
        except Exception as e:
            self.logger.log_error("Trojan parse failed", f"Error: {str(e)}")
            return None
    
    def parse_configuration(self, protocol: str, raw_config: str) -> Optional[VPNConfig]:
        """Parse configuration based on protocol type"""
        try:
            if protocol == 'vmess':
                return self.parse_vmess_configuration(raw_config)
            elif protocol == 'vless':
                return self.parse_vless_configuration(raw_config)
            elif protocol == 'ss':
                return self.parse_shadowsocks_configuration(raw_config)
            elif protocol == 'trojan':
                return self.parse_trojan_configuration(raw_config)
            else:
                self.logger.log_error("Unsupported protocol", f"Protocol: {protocol}")
                return None
                
        except Exception as e:
            self.logger.log_error(f"{protocol.upper()} parse exception",
                                f"Config: {raw_config[:50]}... - Error: {str(e)}")
            return None


# =============================================================================
# ENHANCED SCANNER ENGINE
# =============================================================================

class EnhancedVPNScanner:
    """
    Enhanced VPN configuration scanner with:
    - Comprehensive configuration decoding
    - Advanced performance testing
    - Multi-dimensional quality assessment
    - Automated execution scheduling
    """
    
    def __init__(self, config: ScannerConfig = None):
        self.config = config or ScannerConfig()
        self.logger = EnterpriseLogger()
        self.parser = ConfigurationParser()
        self.tester = PerformanceTester(self.config)
        
        self.performance_stats = {
            'start_time': None,
            'total_processed': 0,
            'valid_configs': 0,
            'failed_tests': 0,
            'duplicates_found': 0,
            'avg_latency': 0,
            'avg_performance_score': 0
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
        """Make enterprise-grade HTTP request"""
        try:
            headers = {
                'User-Agent': 'RebelDev-Enhanced-Scanner/4.0.0',
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
            if len(response.content) > 10 * 1024 * 1024:
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
    
    async def _process_configuration_batch(self, protocol: str, raw_configs: List[str]) -> List[VPNConfig]:
        """
        Process batch of configurations with async performance testing
        """
        validated_configs = []
        
        # Parse configurations
        parsed_configs = []
        for raw_config in raw_configs:
            if not raw_config or raw_config.startswith(('#', '//')):
                continue
            
            config = self.parser.parse_configuration(protocol, raw_config)
            if config and config.config_hash not in self.unique_configs:
                parsed_configs.append(config)
                self.unique_configs.add(config.config_hash)
            elif config:
                self.performance_stats['duplicates_found'] += 1
        
        self.performance_stats['total_processed'] += len(parsed_configs)
        
        # Performance test configurations concurrently
        tasks = []
        for config in parsed_configs:
            task = self.tester.comprehensive_performance_test(config)
            tasks.append(task)
        
        # Wait for all tests to complete
        tested_configs = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect valid configurations
        for tested_config in tested_configs:
            if isinstance(tested_config, VPNConfig) and tested_config.is_valid:
                validated_configs.append(tested_config)
                self.performance_stats['valid_configs'] += 1
            else:
                self.performance_stats['failed_tests'] += 1
        
        # Sort by performance score
        validated_configs.sort(key=lambda x: x.performance_score, reverse=True)
        
        return validated_configs
    
    async def scan_protocol(self, protocol: str) -> List[VPNConfig]:
        """
        Execute complete scanning pipeline for specific protocol
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
        
        self.logger.log_performance("Configurations fetched",
                                  f"Protocol: {protocol} - Count: {len(raw_configs)}")
        
        # Process configurations
        validated_configs = await self._process_configuration_batch(protocol, raw_configs)
        
        self.logger.log_operation("Protocol scan completed",
                                f"Protocol: {protocol} - Valid: {len(validated_configs)}")
        
        return validated_configs
    
    def generate_detailed_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        duration = datetime.utcnow() - self.performance_stats['start_time']
        
        # Calculate average metrics
        all_configs = []
        for configs in self.validated_configs.values():
            all_configs.extend(configs)
        
        if all_configs:
            avg_latency = sum(c.latency for c in all_configs if c.latency) // len(all_configs)
            avg_score = sum(c.performance_score for c in all_configs) / len(all_configs)
        else:
            avg_latency = 0
            avg_score = 0
        
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
                ),
                'average_latency_ms': avg_latency,
                'average_performance_score': round(avg_score, 2)
            },
            'protocol_summary': {
                protocol: {
                    'count': len(configs),
                    'avg_latency': sum(c.latency for c in configs if c.latency) // max(len(configs), 1),
                    'avg_score': sum(c.performance_score for c in configs) / max(len(configs), 1)
                } for protocol, configs in self.validated_configs.items()
            },
            'top_performers': {
                protocol: [
                    {
                        'host': config.host,
                        'latency': config.latency,
                        'performance_score': round(config.performance_score, 2),
                        'remark': config.remark
                    } for config in sorted(configs, key=lambda x: x.performance_score, reverse=True)[:3]
                ] for protocol, configs in self.validated_configs.items()
            }
        }
        
        return report
    
    def save_enhanced_configurations(self):
        """Save validated configurations with enhanced formatting and analytics"""
        try:
            os.makedirs(self.config.OUTPUT_DIRECTORY, exist_ok=True)
            timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            
            for protocol, configs in self.validated_configs.items():
                if not configs:
                    continue
                
                # Generate primary protocol file
                filename = f"{self.config.OUTPUT_DIRECTORY}/{protocol}.txt"
                self._write_enhanced_configuration_file(filename, configs, timestamp, protocol)
                
                # Generate SSR file for shadowsocks
                if protocol == 'ss':
                    ssr_filename = f"{self.config.OUTPUT_DIRECTORY}/ssr.txt"
                    self._write_enhanced_configuration_file(ssr_filename, configs, timestamp, 'ssr')
            
            # Generate performance report
            self._save_performance_report(timestamp)
            
            self.logger.log_operation("Enhanced configurations saved", 
                                    f"Directory: {self.config.OUTPUT_DIRECTORY}")
            
        except Exception as e:
            self.logger.log_error("Failed to save configurations", f"Error: {str(e)}")
            raise
    
    def _write_enhanced_configuration_file(self, filename: str, configs: List[VPNConfig], 
                                         timestamp: str, protocol: str):
        """Write enhanced configuration file with performance metrics"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # Enhanced header with comprehensive analytics
                f.write("# =============================================================================\n")
                f.write("# RebelDev Enhanced VPN Configurations\n")
                f.write("# =============================================================================\n")
                f.write(f"# Protocol: {protocol.upper()}\n")
                f.write(f"# Generated: {timestamp}\n")
                f.write(f"# Total Configurations: {len(configs)}\n")
                f.write(f"# Average Latency: {sum(c.latency for c in configs if c.latency) // len(configs)}ms\n")
                f.write(f"# Average Performance Score: {sum(c.performance_score for c in configs) / len(configs):.2f}\n")
                f.write(f"# Source: {self.config.SOURCE_REPOSITORY}\n")
                f.write(f"# Scanner Version: 4.0.0\n")
                f.write("# Security Level: ENTERPRISE_GRADE\n")
                f.write("# Performance Metrics: Latency, Jitter, Packet Loss, Relay Delay\n")
                f.write("# =============================================================================\n\n")
                
                # Write configurations with performance indicators
                for i, config in enumerate(configs, 1):
                    # Add performance comment
                    perf_comment = f"# Performance: {config.latency}ms latency, Score: {config.performance_score:.2f}"
                    if config.jitter:
                        perf_comment += f", Jitter: {config.jitter}ms"
                    if config.packet_loss:
                        perf_comment += f", Loss: {config.packet_loss:.1%}"
                    
                    f.write(f"{perf_comment}\n")
                    f.write(f"{config.raw_config}\n")
                    
                    if i < len(configs):  # Add spacing between configs
                        f.write("\n")
            
            self.logger.log_performance("Enhanced configuration file written", f"File: {filename}")
            
        except IOError as e:
            self.logger.log_error("File write operation failed", f"File: {filename} - Error: {str(e)}")
            raise
    
    def _save_performance_report(self, timestamp: str):
        """Save detailed performance report"""
        try:
            report = self.generate_detailed_report()
            report_filename = f"{self.config.OUTPUT_DIRECTORY}/performance_report.json"
            
            with open(report_filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self.logger.log_operation("Performance report saved", f"File: {report_filename}")
            
        except Exception as e:
            self.logger.log_error("Failed to save performance report", f"Error: {str(e)}")
    
    async def execute_enhanced_scan(self) -> bool:
        """
        Execute complete enhanced scanning pipeline
        Returns: Boolean indicating overall success
        """
        try:
            self.performance_stats['start_time'] = datetime.utcnow()
            self.logger.log_operation("Enhanced scan pipeline initiated", "Status: STARTED")
            
            # Scan all protocols concurrently
            scan_tasks = []
            for protocol in self.sources.keys():
                task = self.scan_protocol(protocol)
                scan_tasks.append(task)
            
            # Wait for all protocol scans to complete
            results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            # Process results
            for i, protocol in enumerate(self.sources.keys()):
                try:
                    result = results[i]
                    if isinstance(result, list):
                        self.validated_configs[protocol] = result
                    else:
                        self.logger.log_error(f"Protocol scan failed: {protocol}", f"Error: {str(result)}")
                except Exception as e:
                    self.logger.log_error(f"Protocol result processing failed: {protocol}", f"Error: {str(e)}")
                    continue
            
            # Save results
            if any(self.validated_configs.values()):
                self.save_enhanced_configurations()
                
                # Generate and log final report
                report = self.generate_detailed_report()
                self._log_enhanced_report(report)
                
                self.logger.log_operation("Enhanced scan pipeline completed", "Status: SUCCESS")
                return True
            else:
                self.logger.log_operation("Enhanced scan pipeline completed", "Status: NO_VALID_CONFIGS")
                return False
                
        except Exception as e:
            self.logger.log_error("Enhanced scan pipeline failed", f"Error: {str(e)}")
            return False
    
    def _log_enhanced_report(self, report: Dict[str, Any]):
        """Log comprehensive enhanced report"""
        self.logger.log_operation("ENHANCED_SCAN_REPORT", "BEGIN")
        
        for section, data in report.items():
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, dict):
                        for subkey, subvalue in value.items():
                            self.logger.log_performance(f"{section}.{key}.{subkey}", subvalue)
                    else:
                        self.logger.log_performance(f"{section}.{key}", value)
            else:
                self.logger.log_performance(section, data)
        
        self.logger.log_operation("ENHANCED_SCAN_REPORT", "END")


# =============================================================================
# SCHEDULED EXECUTION MANAGER
# =============================================================================

class ScheduledExecutionManager:
    """
    Manager for scheduled execution with comprehensive monitoring
    and automatic hourly execution
    """
    
    def __init__(self):
        self.scanner = EnhancedVPNScanner()
        self.logger = self.scanner.logger
        self.is_running = False
    
    async def execute_scheduled_scan(self) -> int:
        """
        Execute scheduled scan with comprehensive monitoring
        """
        try:
            if self.is_running:
                self.logger.log_operation("Scheduled execution", "SKIPPED - Already running")
                return 1
            
            self.is_running = True
            self.logger.log_operation("Scheduled execution manager", "INITIALIZED")
            
            success = await self.scanner.execute_enhanced_scan()
            
            if success:
                self.logger.log_operation("Scheduled execution", "COMPLETED_SUCCESS")
                return 0
            else:
                self.logger.log_operation("Scheduled execution", "COMPLETED_NO_CONFIGS")
                return 1
            
        except KeyboardInterrupt:
            self.logger.log_operation("Scheduled execution", "INTERRUPTED_BY_USER")
            return 130
            
        except Exception as e:
            self.logger.log_error("Scheduled execution", f"CRITICAL_FAILURE: {str(e)}")
            return 2
        finally:
            self.is_running = False
    
    def start_continuous_monitoring(self):
        """
        Start continuous monitoring with hourly execution
        """
        async def monitoring_loop():
            while True:
                try:
                    self.logger.log_operation("Continuous monitoring", "EXECUTING_HOURLY_SCAN")
                    await self.execute_scheduled_scan()
                    
                    # Wait for 1 hour before next execution
                    self.logger.log_operation("Continuous monitoring", "SLEEPING_1_HOUR")
                    await asyncio.sleep(3600)  # 1 hour
                    
                except Exception as e:
                    self.logger.log_error("Continuous monitoring error", f"Error: {str(e)}")
                    await asyncio.sleep(300)  # Wait 5 minutes before retry
        
        # Start monitoring in background
        asyncio.create_task(monitoring_loop())
        self.logger.log_operation("Continuous monitoring", "STARTED")


# =============================================================================
# ENHANCED ENTRY POINT
# =============================================================================

async def main():
    """
    Enhanced entry point with scheduled execution
    """
    execution_manager = ScheduledExecutionManager()
    
    # Start continuous monitoring
    execution_manager.start_continuous_monitoring()
    
    # Also execute immediate scan
    exit_code = await execution_manager.execute_scheduled_scan()
    return exit_code


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
