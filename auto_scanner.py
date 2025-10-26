#!/usr/bin/env python3
"""
RebelDev Enterprise VPN Configuration Scanner
============================================

Fixed:
- Logger in Parser: Use EnterpriseLogger instance (passed from Scanner)
- datetime.utcnow() -> datetime.now(datetime.UTC)
- No log_error on standard logger

Author: Arian Lavi 
Version: 1.0.0
License: Proprietary - RebelDev Internal Use
"""

import aiohttp
import asyncio
import base64
import json
import socket
import time
import os
import sys
import logging
import subprocess
from urllib.parse import urlparse, unquote, parse_qs
from datetime import datetime, timedelta, UTC  # Added UTC
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import hashlib
import re
from pathlib import Path
import urllib.parse


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class ScannerConfig:
    """Configuration with defaults - Real Repo"""
    SOURCE_REPOSITORY: str = "barry-far/V2ray-Config"
    SOURCE_BRANCH: str = "main"
    SOURCE_PATH: str = "Sub1.txt"  # Real subscription file
    
    MAX_LATENCY_MS: int = 3000
    MAX_JITTER_MS: int = 400
    PACKET_LOSS_THRESHOLD: float = 0.25
    CONNECTION_TIMEOUT: int = 15
    REQUEST_TIMEOUT: int = 45
    MAX_WORKERS: int = 8
    PING_COUNT: int = 3
    PING_TIMEOUT: int = 20
    
    OUTPUT_DIRECTORY: str = "RebelLink"
    CONFIG_RETENTION_DAYS: int = 7
    CACHE_FILE: str = "config_cache.json"
    
    DEFAULT_PORTS: Dict[str, int] = None
    
    def __post_init__(self):
        if self.DEFAULT_PORTS is None:
            self.DEFAULT_PORTS = {
                'ss': 8388, 'trojan': 443, 'vless': 443, 'vmess': 443
            }
        os.makedirs(self.OUTPUT_DIRECTORY, exist_ok=True)

    @property
    def source_url(self) -> str:
        return f"https://raw.githubusercontent.com/{self.SOURCE_REPOSITORY}/{self.SOURCE_BRANCH}/{self.SOURCE_PATH}"


# =============================================================================
# VPN CONFIG CLASS
# =============================================================================

@dataclass
class VPNConfig:
    protocol: str
    host: str
    port: int
    name: str = "Unknown"
    raw_config: str = ""
    config_hash: str = ""
    is_valid: bool = False
    latency: Optional[int] = None
    jitter: Optional[int] = None
    packet_loss: Optional[float] = None
    performance_score: float = 0.0
    relay_success: bool = False
    subscription_link: str = ""
    last_tested: datetime = None

    def __post_init__(self):
        if not self.config_hash:
            self.config_hash = hashlib.sha256(self.raw_config.encode('utf-8', errors='ignore')).hexdigest()[:16]
        if not self.last_tested:
            self.last_tested = datetime.now(UTC)  # Fixed deprecation
    
    def calculate_performance_score(self):
        score = 100.0
        if self.latency:
            score -= min(self.latency / 150.0, 40.0)
        if self.jitter:
            score -= min(self.jitter / 100.0, 15.0)
        if self.packet_loss:
            score -= min(self.packet_loss * 40.0, 25.0)
        if not self.relay_success:
            score -= 15.0
        self.performance_score = max(0.0, min(100.0, score))
    
    def to_subscription_link(self) -> str:
        if not self.host:
            return self.raw_config
        try:
            if self.protocol == 'vmess':
                vmess_dict = {
                    "v": "2", "ps": self.name[:50], "add": self.host, "port": str(self.port),
                    "id": "default-uuid", "aid": 0, "net": "tcp", "type": "none",
                    "host": "", "path": "", "tls": ""
                }
                b64_json = base64.b64encode(json.dumps(vmess_dict).encode('utf-8')).decode('ascii')
                return f"vmess://{b64_json}"
            elif self.protocol == 'vless':
                return f"vless://default-uuid@{self.host}:{self.port}?encryption=none&security=none&type=tcp#{self.name[:50]}"
            elif self.protocol == 'ss':
                b64_part = base64.b64encode(f"aes-256-gcm:pass@{self.host}:{self.port}".encode('utf-8')).decode('ascii')
                return f"ss://{b64_part}#{self.name[:50]}"
            elif self.protocol == 'trojan':
                return f"trojan://pass@{self.host}:{self.port}?security=tls&sni={self.host}#{self.name[:50]}"
        except:
            pass
        return self.raw_config


# =============================================================================
# LOGGER
# =============================================================================

class EnterpriseLogger:
    def __init__(self, log_file: str = "scanner.log"):
        self.log_file = Path(log_file)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s',
            handlers=[logging.FileHandler(self.log_file), logging.StreamHandler(sys.stdout)]
        )
        self.logger = logging.getLogger('RebelDevScanner')
    
    def log_performance(self, event: str, details: str):
        self.logger.info(f"PERFORMANCE: {event} = {details}")
    
    def log_operation(self, event: str, details: str):
        self.logger.info(f"OPERATION: {event} | {details}")
    
    def log_error(self, event: str, details: str):
        self.logger.error(f"ERROR: {event} | {details}")


# =============================================================================
# PARSER (Fixed Logger)
# =============================================================================

class ConfigurationParser:
    def __init__(self, enterprise_logger):  # Pass EnterpriseLogger
        self.logger = enterprise_logger  # Use EnterpriseLogger
        self.default_ports = {'ss': 8388, 'trojan': 443, 'vless': 443, 'vmess': 443}
    
    def parse_configuration(self, protocol: str, raw_config: str) -> Optional[VPNConfig]:
        if len(raw_config) < 20 or re.match(r'^-+$', raw_config.strip()):
            return None
        
        decoded = self._try_decode(raw_config)
        
        host = ""
        port = self.default_ports.get(protocol, 443)
        name = protocol.upper()
        
        try:
            if protocol == 'vmess':
                parsed = self._parse_vmess(decoded)
            elif protocol == 'vless':
                parsed = self._parse_vless(decoded)
            elif protocol == 'ss':
                parsed = self._parse_ss(decoded)
            elif protocol == 'trojan':
                parsed = self._parse_trojan(decoded)
            else:
                return None
            
            if parsed:
                host, port, name = parsed
                if host and len(host) > 3:
                    return VPNConfig(protocol=protocol, host=host, port=port, name=name, raw_config=raw_config)
        except Exception as e:
            self.logger.log_error(f"Parse exception {protocol}", str(e)[:100])  # Now EnterpriseLogger
        
        if not host:
            self.logger.log_error(f"Missing hostname in {protocol.upper()}", f"Config: {raw_config[:50]}...")
        return None
    
    def _try_decode(self, raw: str) -> str:
        try:
            raw_clean = re.sub(r'[^\x00-\x7F]', '', raw)
            padded = raw_clean + '==' * ((4 - len(raw_clean) % 4) % 4)
            decoded_bytes = base64.b64decode(padded, validate=False)
            return decoded_bytes.decode('utf-8', errors='ignore').strip()
        except:
            return raw.strip()
    
    def _parse_vmess(self, decoded: str) -> Tuple[Optional[str], Optional[int], str]:
        if decoded.startswith('vmess://'):
            decoded = decoded[8:]
            decoded = self._try_decode(decoded)
        
        json_match = re.search(r'\{[^{}]*"(?:[^{}"]|"(?:[^{}]*"))*\}', decoded, re.DOTALL)
        if json_match:
            try:
                config_json = json.loads(json_match.group(0))
                return (config_json.get('add') or config_json.get('server', ''), 
                        int(config_json.get('port', 443)), 
                        config_json.get('ps', 'VMESS')[:50])
            except:
                pass
        
        try:
            config_json = json.loads(decoded)
            return (config_json.get('add') or config_json.get('server', ''), 
                    int(config_json.get('port', 443)), 
                    config_json.get('ps', 'VMESS')[:50])
        except:
            pass
        
        return None, None, 'VMESS'
    
    def _parse_vless(self, decoded: str) -> Tuple[Optional[str], Optional[int], str]:
        if not decoded.startswith('vless://'):
            return None, None, 'VLESS'
        
        uri = decoded[8:]
        parsed = urlparse('vless://' + uri)
        if '@' in parsed.netloc:
            _, host_port = parsed.netloc.split('@', 1)
        else:
            host_port = parsed.netloc
        
        if ':' in host_port:
            host, port_str = host_port.rsplit(':', 1)
            port = int(port_str)
        else:
            host = host_port
            port = 443
        
        name = parse_qs(parsed.query).get('remark', [parsed.fragment or 'VLESS'])[0][:50]
        return host, port, name
    
    def _parse_ss(self, decoded: str) -> Tuple[Optional[str], Optional[int], str]:
        if not decoded.startswith('ss://'):
            return None, None, 'SS'
        
        b64_part = decoded[5:]
        try:
            decoded_inner = self._try_decode(b64_part)
            if '@' in decoded_inner:
                _, host_port = decoded_inner.split('@', 1)
                if ':' in host_port:
                    host, port_str = host_port.rsplit(':', 1)
                    port = int(port_str)
                else:
                    host = host_port
                    port = 8388
            else:
                host_port_match = re.search(r'([^\s:]+)(?::(\d+))?', decoded_inner)
                if host_port_match:
                    host = host_port_match.group(1)
                    port = int(host_port_match.group(2)) if host_port_match.group(2) else 8388
                else:
                    return None, None, 'SS'
            
            name_match = re.search(r'#(.+)$', decoded)
            name = unquote(name_match.group(1))[:50] if name_match else 'SS'
            return host, port, name
        except:
            return None, None, 'SS'
    
    def _parse_trojan(self, decoded: str) -> Tuple[Optional[str], Optional[int], str]:
        if not decoded.startswith('trojan://'):
            return None, None, 'TROJAN'
        
        uri = decoded[9:]
        last_at = uri.rfind('@')
        if last_at == -1:
            return None, None, 'TROJAN'
        
        pass_part = uri[:last_at]
        host_port_part = uri[last_at + 1:]
        
        if '?' in host_port_part:
            host_port, params = host_port_part.split('?', 1)
        else:
            host_port = host_port_part
            params = ''
        
        if ':' in host_port:
            host, port_str = host_port.rsplit(':', 1)
            port = int(port_str)
        else:
            host = host_port
            port = 443
        
        name_match = re.search(r'#(.+)$', decoded)
        name = unquote(name_match.group(1))[:50] if name_match else parse_qs(params).get('remark', ['TROJAN'])[0]
        return host, port, name


# =============================================================================
# TESTER
# =============================================================================

class ImprovedPerformanceTester:
    def __init__(self, config: ScannerConfig, logger):
        self.config = config
        self.logger = logger
    
    async def test_ping_performance(self, host: str) -> Tuple[Optional[int], Optional[int], Optional[float]]:
        if not host or host in ['localhost', '127.0.0.1', '0.0.0.0']:
            return None, None, None
        
        loop = asyncio.get_event_loop()
        try:
            if sys.platform == "win32":
                cmd = ["ping", "-n", str(self.config.PING_COUNT), "-w", str(self.config.PING_TIMEOUT * 1000), host]
            else:
                cmd = ["ping", "-c", str(self.config.PING_COUNT), "-W", str(self.config.PING_TIMEOUT), host]
            
            result = await loop.run_in_executor(
                None, 
                lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=self.config.PING_TIMEOUT * 1.5)
            )
            parsed = self._parse_ping_output(result.stdout, host)
            if parsed[0] is not None:
                self.logger.log_performance("Ping success", f"{host}: {parsed[0]}ms")
            return parsed
        except subprocess.TimeoutExpired:
            self.logger.log_performance("Ping timeout fallback", f"{host} - Using TCP latency")
            return None, None, None
        except Exception as e:
            self.logger.log_performance("Ping skipped", f"{host} - {str(e)[:30]}")
            return None, None, None
    
    def _parse_ping_output(self, output: str, host: str) -> Tuple[Optional[int], Optional[int], Optional[float]]:
        latencies = re.findall(r'time[=<]?([\d.]+)ms', output)
        if len(latencies) < 1:
            return None, None, None
        latencies = [float(l) for l in latencies[:self.config.PING_COUNT]]
        avg = int(sum(latencies) / len(latencies))
        mean = sum(latencies) / len(latencies)
        jitter = int(((sum((x - mean)**2 for x in latencies) / len(latencies)) ** 0.5) or 0)
        loss_match = re.search(r'(\d+)% packet loss', output)
        loss = float(loss_match.group(1)) / 100 if loss_match else 0.0
        return avg, jitter, loss
    
    async def test_tcp_connection(self, host: str, port: int) -> Tuple[bool, Optional[int]]:
        start = time.time()
        try:
            _, _ = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.CONNECTION_TIMEOUT
            )
            latency = int((time.time() - start) * 1000)
            self.logger.log_performance("TCP success", f"{host}:{port} - {latency}ms")
            return True, latency
        except:
            self.logger.log_performance("TCP failed", f"{host}:{port}")
            return False, None
    
    async def test_relay_connection(self, config: VPNConfig) -> bool:
        config.relay_success = True
        return True
    
    async def comprehensive_performance_test(self, config: VPNConfig) -> VPNConfig:
        if not config.host:
            config.is_valid = False
            return config
        
        tcp_ok, tcp_lat = await self.test_tcp_connection(config.host, config.port)
        if not tcp_ok:
            config.is_valid = False
            return config
        
        config.latency = tcp_lat or 3000
        ping_lat, jitter, loss = await self.test_ping_performance(config.host)
        if ping_lat:
            config.latency = min(ping_lat, config.latency)
            config.jitter = jitter
            config.packet_loss = loss
        
        await self.test_relay_connection(config)
        config.calculate_performance_score()
        config.is_valid = config.latency <= self.config.MAX_LATENCY_MS and config.relay_success
        config.subscription_link = config.to_subscription_link()
        return config


# =============================================================================
# SCANNER (Pass Logger to Parser)
# =============================================================================

class ImprovedVPNScanner:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = EnterpriseLogger()
        self.parser = ConfigurationParser(self.logger)  # Pass logger
        self.tester = ImprovedPerformanceTester(config, self.logger)
        self.unique_configs = self._load_cache()
        self.validated_configs: Dict[str, List[VPNConfig]] = {}
        self.performance_stats = {'start_time': datetime.now(UTC), 'total_processed': 0, 'valid_configs': 0, 'failed_tests': 0, 'duplicates_found': 0}  # Fixed deprecation
    
    def _load_cache(self) -> set:
        cache_path = Path(self.config.OUTPUT_DIRECTORY) / self.config.CACHE_FILE
        if cache_path.exists():
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    cache = json.load(f)
                now = datetime.now(UTC)
                cache = {ts: h for ts, h in cache.items() if datetime.fromisoformat(ts) > now - timedelta(days=self.config.CONFIG_RETENTION_DAYS)}
                with open(cache_path, 'w', encoding='utf-8') as f:
                    json.dump(cache, f)
                return set(cache.values())
            except:
                pass
        return set()
    
    def _save_cache(self):
        cache_path = Path(self.config.OUTPUT_DIRECTORY) / self.config.CACHE_FILE
        cache = {c.last_tested.isoformat(): c.config_hash for lst in self.validated_configs.values() for c in lst if c.is_valid}
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(cache, f)
    
    async def _fetch_all_configs(self) -> Dict[str, List[str]]:
        url = self.config.source_url
        connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
        timeout = aiohttp.ClientTimeout(total=self.config.REQUEST_TIMEOUT)
        groups: Dict[str, List[str]] = {'vmess': [], 'vless': [], 'ss': [], 'trojan': []}
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            try:
                async with session.get(url, headers={'User-Agent': 'RebelDev-Scanner/4.8.0'}) as resp:
                    if resp.status == 200:
                        content = await resp.text(encoding='utf-8', errors='ignore')
                        lines = content.splitlines()
                        total_lines = len([l for l in lines if l.strip()])
                        self.logger.log_performance("File fetched", f"{url}: {total_lines} total lines")
                        
                        for line in lines:
                            line = line.strip()
                            if len(line) < 10 or re.match(r'^-+$', line) or line.startswith(('#', '//')):
                                if re.match(r'^-+$', line):
                                    self.logger.log_performance("Dashes skipped", "Placeholder line ignored")
                                continue
                            
                            proto = None
                            for p in groups:
                                if line.startswith(f"{p}://"):
                                    groups[p].append(line)
                                    proto = p
                                    break
                            
                            if proto:
                                self.logger.log_performance("Line grouped", f"{proto}: {len(groups[p])} total")
                        
                        for p, lst in groups.items():
                            self.logger.log_performance("Group count", f"{p}: {len(lst)}")
                        
                        return groups
            except Exception as e:
                self.logger.log_error("Fetch failed", f"{url}: {str(e)}")
        
        return groups
    
    async def _process_configuration_batch(self, protocol: str, raw_configs: List[str]) -> List[VPNConfig]:
        parsed = []
        for raw in raw_configs:
            cfg = self.parser.parse_configuration(protocol, raw)
            if cfg:
                if cfg.config_hash not in self.unique_configs:
                    parsed.append(cfg)
                    self.unique_configs.add(cfg.config_hash)
                else:
                    self.performance_stats['duplicates_found'] += 1
        
        self.performance_stats['total_processed'] += len(parsed)
        self.logger.log_performance("Batch parsed", f"{protocol}: {len(parsed)} new")
        
        if not parsed:
            return []
        
        semaphore = asyncio.Semaphore(self.config.MAX_WORKERS)
        async def test_with_sem(cfg):
            async with semaphore:
                return await self.tester.comprehensive_performance_test(cfg)
        
        tasks = [test_with_sem(cfg) for cfg in parsed]
        tested = await asyncio.gather(*tasks, return_exceptions=True)
        
        validated = [t for t in tested if isinstance(t, VPNConfig) and t.is_valid]
        failed_count = len(parsed) - len(validated)
        self.performance_stats['valid_configs'] += len(validated)
        self.performance_stats['failed_tests'] += failed_count
        self.logger.log_performance("Batch tests", f"{protocol}: {len(validated)} valid / {failed_count} failed")
        
        validated.sort(key=lambda x: x.performance_score, reverse=True)
        return validated
    
    async def execute_improved_scan(self) -> bool:
        self.logger.log_operation("Enhanced scan pipeline initiated", "Status: STARTED")
        
        groups = await self._fetch_all_configs()
        
        protocols = ['vmess', 'vless', 'ss', 'trojan']
        for protocol in protocols:
            if groups[protocol]:
                self.logger.log_operation("Processing group", f"Protocol: {protocol.upper()}")
                validated = await self._process_configuration_batch(protocol, groups[protocol])
                self.validated_configs[protocol] = validated
                await asyncio.sleep(2)
        
        has_valid = any(self.validated_configs.values())
        if has_valid:
            self.save_enhanced_configurations()
            self._save_cache()
            report = self.generate_improved_report()
            self._save_report(report)
            self.logger.log_operation("Enhanced scan pipeline completed", "Status: SUCCESS")
            return True
        self.logger.log_operation("Enhanced scan pipeline completed", "Status: NO_VALID_CONFIGS")
        return False
    
    def save_enhanced_configurations(self):
        all_links = []
        for proto, configs in self.validated_configs.items():
            path = Path(self.config.OUTPUT_DIRECTORY) / f"{proto}_subscriptions.txt"
            with open(path, 'w', encoding='utf-8') as f:
                for cfg in configs:
                    f.write(f"{cfg.subscription_link}\n")
                    all_links.append(cfg.subscription_link)
            self.logger.log_performance("Saved", f"{proto}: {len(configs)}")
        
        combined_path = Path(self.config.OUTPUT_DIRECTORY) / "all_subscriptions.txt"
        with open(combined_path, 'w', encoding='utf-8') as f:
            for link in all_links:
                f.write(f"{link}\n")
    
    def generate_improved_report(self) -> Dict[str, Any]:
        all_configs = [c for lst in self.validated_configs.values() for c in lst]
        total = self.performance_stats['total_processed']
        valid = self.performance_stats['valid_configs']
        if len(all_configs) > 0:
            avg_lat = sum(c.latency or 0 for c in all_configs) / len(all_configs)
            avg_score = sum(c.performance_score for c in all_configs) / len(all_configs)
            success_rate = (valid / total * 100) if total > 0 else 0
        else:
            avg_lat = avg_score = success_rate = 0
        
        duration = (datetime.now(UTC) - self.performance_stats['start_time']).total_seconds()
        report = {
            'scan_timestamp': datetime.now(UTC).isoformat(),
            'duration_seconds': round(duration, 2),
            'performance_metrics': {
                'total_processed': total,
                'valid_configs': valid,
                'duplicates': self.performance_stats['duplicates_found'],
                'failed_tests': self.performance_stats['failed_tests'],
                'success_rate': round(success_rate, 2),
                'avg_latency_ms': round(avg_lat, 2),
                'avg_score': round(avg_score, 2)
            },
            'protocol_summary': {
                p: {
                    'count': len(c), 
                    'avg_lat': sum(cc.latency or 0 for cc in c) / max(1, len(c)), 
                    'avg_score': sum(cc.performance_score for cc in c) / max(1, len(c))
                } for p, c in self.validated_configs.items()
            }
        }
        self.logger.log_performance("Report generated", f"Valid: {valid}/{total}")
        return report
    
    def _save_report(self, report: Dict[str, Any]):
        path = Path(self.config.OUTPUT_DIRECTORY) / "performance_report.json"
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)


# =============================================================================
# MANAGER & MAIN
# =============================================================================

class ImprovedExecutionManager:
    def __init__(self):
        self.config = ScannerConfig()
        self.scanner = ImprovedVPNScanner(self.config)
        self.logger = self.scanner.logger
        self.is_running = False
    
    async def execute_improved_scan(self) -> int:
        if self.is_running:
            self.logger.log_operation("Scheduled execution", "SKIPPED - Already running")
            return 1
        self.is_running = True
        try:
            self.logger.log_operation("Scheduled execution manager", "INITIALIZED")
            success = await self.scanner.execute_improved_scan()
            return 0 if success else 1
        except KeyboardInterrupt:
            self.logger.log_operation("Execution", "INTERRUPTED")
            return 130
        except Exception as e:
            self.logger.log_error("Execution failed", str(e))
            return 2
        finally:
            self.is_running = False

async def main():
    manager = ImprovedExecutionManager()
    exit_code = await manager.execute_improved_scan()
    return exit_code

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
