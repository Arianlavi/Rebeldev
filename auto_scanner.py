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
from urllib.parse import urlparse, unquote, parse_qs
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import hashlib
import re


# =============================================================================
# IMPROVED CONFIGURATION MANAGEMENT
# =============================================================================

@dataclass
class ScannerConfig:
    """Improved configuration with better timeout handling"""
    
    # Source configuration
    SOURCE_REPOSITORY: str = "Epodonios/v2ray-configs"
    SOURCE_BRANCH: str = "main"
    SOURCE_PATH: str = "Splitted-By-Protocol"
    
    # Performance thresholds - Adjusted for better handling
    MAX_LATENCY_MS: int = 1500  # Increased for global servers
    MAX_JITTER_MS: int = 200    # Increased threshold
    PACKET_LOSS_THRESHOLD: float = 0.3  # More lenient
    CONNECTION_TIMEOUT: int = 8  # Increased timeout
    REQUEST_TIMEOUT: int = 20    # Increased for slow connections
    MAX_WORKERS: int = 8         # Reduced to avoid overloading
    PING_COUNT: int = 2          # Reduced count
    PING_TIMEOUT: int = 5        # Reduced ping timeout
    
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


# =============================================================================
# IMPROVED PERFORMANCE TESTING ENGINE
# =============================================================================

class ImprovedPerformanceTester:
    """
    Improved performance testing with:
    - Better ping timeout handling
    - TCP fallback when ping fails
    - Graceful degradation
    """
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = EnterpriseLogger()
    
    async def test_ping_performance(self, host: str) -> Tuple[Optional[int], Optional[int], Optional[float]]:
        """
        Improved ping testing with better error handling and fallbacks
        """
        try:
            # Skip ping for localhost or invalid hosts
            if host in ['localhost', '127.0.0.1', '0.0.0.0']:
                return None, None, None
            
            # Use system-appropriate ping command
            if sys.platform == "win32":
                cmd = ["ping", "-n", str(self.config.PING_COUNT), "-w", str(self.config.PING_TIMEOUT * 1000), host]
            else:
                cmd = ["ping", "-c", str(self.config.PING_COUNT), "-W", str(self.config.PING_TIMEOUT), host]
            
            self.logger.log_performance("Ping test initiated", f"Host: {host}")
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=self.config.PING_TIMEOUT + 2  # Add buffer
            )
            
            return self._parse_ping_output(result.stdout, host)
            
        except subprocess.TimeoutExpired:
            self.logger.log_performance("Ping test timeout", f"Host: {host}")
            return None, None, None
        except (subprocess.SubprocessError, Exception) as e:
            self.logger.log_performance("Ping test failed", f"Host: {host} - Error: {str(e)}")
            return None, None, None
    
    def _parse_ping_output(self, output: str, host: str) -> Tuple[Optional[int], Optional[int], Optional[float]]:
        """Parse ping command output with improved error handling"""
        try:
            # Different patterns for different OS
            latency_patterns = [
                r'time=([\d.]+)ms',  # Linux/Mac
                r'time[=<]([\d.]+)ms',  # Windows variations
                r'(\d+\.\d+)\s*ms'  # Generic
            ]
            
            latencies = []
            for pattern in latency_patterns:
                matches = re.findall(pattern, output)
                if matches:
                    latencies.extend([float(match) for match in matches])
                    break
            
            if not latencies:
                self.logger.log_performance("No ping responses", f"Host: {host}")
                return None, None, None
            
            # Calculate metrics
            avg_latency = int(sum(latencies) / len(latencies))
            
            # Calculate jitter
            mean = sum(latencies) / len(latencies)
            variance = sum((x - mean) ** 2 for x in latencies) / len(latencies)
            jitter = int(variance ** 0.5)
            
            # Extract packet loss
            loss_patterns = [
                r'(\d+)% packet loss',
                r'Lost\s*=\s*(\d+)',
                r'(\d+)\s*% loss'
            ]
            
            packet_loss = 0.0
            for pattern in loss_patterns:
                loss_match = re.search(pattern, output)
                if loss_match:
                    packet_loss = float(loss_match.group(1)) / 100
                    break
            
            self.logger.log_performance("Ping test successful", 
                                      f"Host: {host} - Latency: {avg_latency}ms")
            
            return avg_latency, jitter, packet_loss
            
        except Exception as e:
            self.logger.log_error("Ping output parsing failed", f"Host: {host} - Error: {str(e)}")
            return None, None, None
    
    async def test_tcp_connection(self, host: str, port: int) -> Tuple[bool, Optional[int]]:
        """
        Test TCP connection with latency measurement
        Returns: (success, latency_ms)
        """
        try:
            start_time = time.time()
            
            # Create socket with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.CONNECTION_TIMEOUT)
            
            # Attempt connection
            sock.connect((host, port))
            sock.close()
            
            end_time = time.time()
            latency = int((end_time - start_time) * 1000)
            
            self.logger.log_performance("TCP test successful", f"{host}:{port} - {latency}ms")
            return True, latency
            
        except socket.timeout:
            self.logger.log_performance("TCP test timeout", f"{host}:{port}")
            return False, None
        except (socket.gaierror, ConnectionRefusedError, OSError) as e:
            self.logger.log_performance("TCP test failed", f"{host}:{port} - {str(e)}")
            return False, None
        except Exception as e:
            self.logger.log_error("Unexpected TCP error", f"{host}:{port} - {str(e)}")
            return False, None
    
    async def comprehensive_performance_test(self, config: VPNConfig) -> VPNConfig:
        """
        Improved performance testing with graceful fallbacks
        """
        try:
            # First, try TCP connection test (most important for VPN)
            tcp_success, tcp_latency = await self.test_tcp_connection(config.host, config.port)
            
            if not tcp_success:
                config.is_valid = False
                self.logger.log_performance("Performance test failed - TCP unreachable", 
                                          f"{config.host}:{config.port}")
                return config
            
            # Set TCP latency as baseline
            config.latency = tcp_latency
            config.relay_delay = tcp_latency
            
            # Try ping test, but don't fail if it doesn't work
            ping_latency, jitter, packet_loss = await self.test_ping_performance(config.host)
            
            if ping_latency:
                # Use ping latency if available (more accurate)
                config.latency = ping_latency
                config.jitter = jitter
                config.packet_loss = packet_loss
                self.logger.log_performance("Using ping metrics", 
                                          f"{config.host}:{config.port} - Latency: {ping_latency}ms")
            else:
                # Fallback to TCP latency
                config.jitter = 0
                config.packet_loss = 0.0
                self.logger.log_performance("Using TCP metrics (ping blocked)", 
                                          f"{config.host}:{config.port} - Latency: {tcp_latency}ms")
            
            # Calculate performance score
            config.calculate_performance_score()
            
            # More lenient validation - focus on TCP connectivity
            if (config.latency <= self.config.MAX_LATENCY_MS and 
                tcp_success):
                config.is_valid = True
                
                self.logger.log_performance(
                    "Performance test passed",
                    f"{config.host}:{config.port} - Latency: {config.latency}ms, TCP: OK"
                )
            else:
                config.is_valid = False
                self.logger.log_performance(
                    "Performance test failed - Poor metrics",
                    f"{config.host}:{config.port} - Latency: {config.latency}ms"
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
# IMPROVED SCANNER ENGINE
# =============================================================================

class ImprovedVPNScanner:
    """
    Improved VPN scanner with:
    - Better error handling
    - Graceful performance testing
    - Reduced resource usage
    """
    
    def __init__(self, config: ScannerConfig = None):
        self.config = config or ScannerConfig()
        self.logger = EnterpriseLogger()
        self.parser = ConfigurationParser()
        self.tester = ImprovedPerformanceTester(self.config)
        
        self.performance_stats = {
            'start_time': None,
            'total_processed': 0,
            'valid_configs': 0,
            'failed_tests': 0,
            'duplicates_found': 0,
            'ping_failures': 0,
            'tcp_successes': 0
        }
        
        # Initialize source URLs
        self.sources = self._initialize_sources()
        
        # Configuration tracking
        self.unique_configs = set()
        self.validated_configs = {}
    
    def _initialize_sources(self) -> Dict[str, str]:
        """Initialize source URLs"""
        base_url = f"https://raw.githubusercontent.com/{self.config.SOURCE_REPOSITORY}"
        return {
            'vless': f"{base_url}/{self.config.SOURCE_BRANCH}/{self.config.SOURCE_PATH}/vless.txt",
            'vmess': f"{base_url}/{self.config.SOURCE_BRANCH}/{self.config.SOURCE_PATH}/vmess.txt",
            'ss': f"{base_url}/{self.config.SOURCE_BRANCH}/{self.config.SOURCE_PATH}/ss.txt",
            'trojan': f"{base_url}/{self.config.SOURCE_BRANCH}/{self.config.SOURCE_PATH}/trojan.txt"
        }
    
    async def _process_configuration_batch(self, protocol: str, raw_configs: List[str]) -> List[VPNConfig]:
        """
        Process batch of configurations with improved error handling
        """
        validated_configs = []
        
        # Parse configurations first
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
        self.logger.log_performance("Configurations parsed", 
                                  f"Protocol: {protocol} - Count: {len(parsed_configs)}")
        
        # Process in smaller batches to avoid overwhelming the system
        batch_size = 5
        for i in range(0, len(parsed_configs), batch_size):
            batch = parsed_configs[i:i + batch_size]
            
            # Performance test configurations
            tasks = []
            for config in batch:
                task = self.tester.comprehensive_performance_test(config)
                tasks.append(task)
            
            # Wait for batch to complete with timeout
            try:
                batch_timeout = self.config.CONNECTION_TIMEOUT * len(batch) + 30
                tested_configs = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=batch_timeout
                )
                
                # Collect results
                for tested_config in tested_configs:
                    if isinstance(tested_config, Exception):
                        self.performance_stats['failed_tests'] += 1
                        continue
                    
                    if tested_config.is_valid:
                        validated_configs.append(tested_config)
                        self.performance_stats['valid_configs'] += 1
                        self.performance_stats['tcp_successes'] += 1
                    else:
                        self.performance_stats['failed_tests'] += 1
                        
            except asyncio.TimeoutError:
                self.logger.log_error("Batch processing timeout", f"Protocol: {protocol} - Batch: {i//batch_size}")
                self.performance_stats['failed_tests'] += len(batch)
            
            # Small delay between batches to avoid overwhelming
            await asyncio.sleep(1)
        
        # Sort by performance score
        validated_configs.sort(key=lambda x: x.performance_score, reverse=True)
        
        self.logger.log_operation("Batch processing completed",
                                f"Protocol: {protocol} - Valid: {len(validated_configs)}")
        
        return validated_configs
    
    async def scan_protocol(self, protocol: str) -> List[VPNConfig]:
        """
        Execute scanning pipeline for specific protocol with improved reliability
        """
        self.logger.log_operation("Protocol scan initiated", f"Protocol: {protocol.upper()}")
        
        source_url = self.sources.get(protocol)
        if not source_url:
            self.logger.log_error("Invalid protocol specified", f"Protocol: {protocol}")
            return []
        
        try:
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
            
        except Exception as e:
            self.logger.log_error("Protocol scan failed", f"Protocol: {protocol} - Error: {str(e)}")
            return []
    
    def _make_enterprise_request(self, url: str) -> Optional[str]:
        """Make HTTP request with improved error handling"""
        try:
            headers = {
                'User-Agent': 'RebelDev-Improved-Scanner/4.1.0',
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
    
    def generate_improved_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        duration = datetime.utcnow() - self.performance_stats['start_time']
        
        # Calculate average metrics
        all_configs = []
        for configs in self.validated_configs.values():
            all_configs.extend(configs)
        
        if all_configs:
            avg_latency = sum(c.latency for c in all_configs if c.latency) // len(all_configs)
            avg_score = sum(c.performance_score for c in all_configs) / len(all_configs)
            success_rate = (self.performance_stats['valid_configs'] / max(self.performance_stats['total_processed'], 1)) * 100
        else:
            avg_latency = 0
            avg_score = 0
            success_rate = 0
        
        report = {
            'scan_timestamp': datetime.utcnow().isoformat(),
            'duration_seconds': round(duration.total_seconds(), 2),
            'performance_metrics': {
                'total_configurations_processed': self.performance_stats['total_processed'],
                'valid_configurations_found': self.performance_stats['valid_configs'],
                'duplicate_configurations_removed': self.performance_stats['duplicates_found'],
                'failed_connection_tests': self.performance_stats['failed_tests'],
                'tcp_successful_connections': self.performance_stats['tcp_successes'],
                'success_rate': round(success_rate, 2),
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
            'system_metrics': {
                'unique_configurations_tracked': len(self.unique_configs),
                'ping_failures': self.performance_stats['ping_failures'],
                'output_directory': self.config.OUTPUT_DIRECTORY
            }
        }
        
        return report
    
    async def execute_improved_scan(self) -> bool:
        """
        Execute improved scanning pipeline with better reliability
        """
        try:
            self.performance_stats['start_time'] = datetime.utcnow()
            self.logger.log_operation("Improved scan pipeline initiated", "Status: STARTED")
            
            # Scan protocols sequentially to avoid overloading
            for protocol in self.sources.keys():
                try:
                    self.logger.log_operation("Scanning protocol", f"Protocol: {protocol.upper()}")
                    configs = await self.scan_protocol(protocol)
                    
                    if configs:
                        self.validated_configs[protocol] = configs
                        self.logger.log_performance("Protocol scan successful", 
                                                  f"Protocol: {protocol} - Found: {len(configs)}")
                    else:
                        self.logger.log_performance("Protocol scan empty", 
                                                  f"Protocol: {protocol}")
                        
                    # Delay between protocols
                    await asyncio.sleep(2)
                    
                except Exception as e:
                    self.logger.log_error(f"Protocol scan failed: {protocol}", f"Error: {str(e)}")
                    continue
            
            # Save results if we have any valid configurations
            if any(self.validated_configs.values()):
                self.save_enhanced_configurations()
                
                # Generate final report
                report = self.generate_improved_report()
                self._log_improved_report(report)
                
                self.logger.log_operation("Improved scan pipeline completed", "Status: SUCCESS")
                return True
            else:
                self.logger.log_operation("Improved scan pipeline completed", "Status: NO_VALID_CONFIGS")
                return False
                
        except Exception as e:
            self.logger.log_error("Improved scan pipeline failed", f"Error: {str(e)}")
            return False
    
    def _log_improved_report(self, report: Dict[str, Any]):
        """Log comprehensive improved report"""
        self.logger.log_operation("IMPROVED_SCAN_REPORT", "BEGIN")
        
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
        
        self.logger.log_operation("IMPROVED_SCAN_REPORT", "END")


# =============================================================================
# IMPROVED EXECUTION MANAGER
# =============================================================================

class ImprovedExecutionManager:
    """
    Improved execution manager with better resource management
    """
    
    def __init__(self):
        self.scanner = ImprovedVPNScanner()
        self.logger = self.scanner.logger
        self.is_running = False
    
    async def execute_improved_scan(self) -> int:
        """
        Execute improved scan with comprehensive monitoring
        """
        try:
            if self.is_running:
                self.logger.log_operation("Execution", "SKIPPED - Already running")
                return 1
            
            self.is_running = True
            self.logger.log_operation("Improved execution manager", "INITIALIZED")
            
            success = await self.scanner.execute_improved_scan()
            
            if success:
                self.logger.log_operation("Execution", "COMPLETED_SUCCESS")
                return 0
            else:
                self.logger.log_operation("Execution", "COMPLETED_NO_CONFIGS")
                return 1
            
        except KeyboardInterrupt:
            self.logger.log_operation("Execution", "INTERRUPTED_BY_USER")
            return 130
        except Exception as e:
            self.logger.log_error("Execution", f"CRITICAL_FAILURE: {str(e)}")
            return 2
        finally:
            self.is_running = False


# =============================================================================
# IMPROVED ENTRY POINT
# =============================================================================

async def main():
    """
    Improved entry point with better error handling
    """
    try:
        execution_manager = ImprovedExecutionManager()
        exit_code = await execution_manager.execute_improved_scan()
        return exit_code
        
    except Exception as e:
        # Fallback basic logging if everything fails
        print(f"Critical error: {str(e)}")
        return 2


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
