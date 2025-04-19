import time
import threading
import statistics
import subprocess
import re
import socket
import platform
import datetime
import traceback
from collections import defaultdict, deque

class PerformanceMonitor:
    def __init__(self, interval=60):
        """
        Initialize Performance Monitor
        
        Args:
            interval (int): Time between measurements in seconds
        """
        self.interval = interval
        self._monitoring = False
        self._lock = threading.Lock()
        
        # Initialize metrics storage
        self.latency = defaultdict(lambda: deque(maxlen=100))  # Format: {host: deque([latency_values])}
        self.packet_loss = defaultdict(lambda: deque(maxlen=50))  # Format: {host: deque([loss_percentage_values])}
        self.dns_resolution = defaultdict(lambda: deque(maxlen=50))  # Format: {domain: deque([resolution_times])}
        self.historical_metrics = defaultdict(lambda: defaultdict(list))  # Format: {metric_type: {host: [values]}}
        self.connection_retries = defaultdict(int)  # Track connection retry attempts
        self.jitter = defaultdict(lambda: deque(maxlen=50))  # Track network jitter
        self.connection_times = defaultdict(lambda: deque(maxlen=50))  # Track connection establishment times
        
        # Common destinations to monitor
        self.common_destinations = [
            "8.8.8.8",            # Google DNS
            "1.1.1.1",            # Cloudflare DNS
            "www.google.com",     # Google
            "www.amazon.com",     # Amazon
            "www.microsoft.com",  # Microsoft
            "www.cloudflare.com", # Cloudflare
            "www.github.com",     # GitHub
        ]
        
    def start_monitoring(self):
        """Start continuous performance monitoring in background thread"""
        if self._monitoring:
            return
            
        self._monitoring = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        print("Performance monitoring started")
        
    def stop_monitoring(self):
        """Stop the continuous monitoring thread"""
        self._monitoring = False
        print("Performance monitoring stopped")
        
    def _monitor_loop(self):
        """Internal method for continuous monitoring"""
        while self._monitoring:
            try:
                self.measure_latency()
                self.measure_dns_resolution()
                self.measure_jitter()
                self.measure_connection_times()
                time.sleep(self.interval)
            except Exception as e:
                print(f"Error in monitor loop: {e}")
                traceback.print_exc()
    
    def measure_jitter(self, hosts=None):
        """
        Measure network jitter to specified hosts
        
        Args:
            hosts (list): List of hosts to measure jitter for
        """
        hosts = hosts or self.common_destinations
        
        for host in hosts:
            try:
                jitter_value = self._measure_jitter(host)
                
                with self._lock:
                    if jitter_value is not None:
                        self.jitter[host].append(jitter_value)
                        self.historical_metrics['jitter'][host].append({
                            'timestamp': datetime.datetime.now(),
                            'value': jitter_value
                        })
            
            except Exception as e:
                print(f"Error measuring jitter to {host}: {e}")
    
    def _measure_jitter(self, host):
        """
        Calculate network jitter for a host
        
        Args:
            host (str): Host to measure jitter for
            
        Returns:
            float: Jitter value in milliseconds or None
        """
        try:
            # Run ping with multiple packets
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "10", host]
            else:
                cmd = ["ping", "-c", "10", host]
                
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True, timeout=15)
            
            # Extract ping times
            ping_times = []
            if platform.system().lower() == "windows":
                # Windows format
                for line in output.split('\n'):
                    match = re.search(r'time=(\d+)ms', line)
                    if match:
                        ping_times.append(float(match.group(1)))
            else:
                # Unix format
                for line in output.split('\n'):
                    match = re.search(r'time=([\d.]+) ms', line)
                    if match:
                        ping_times.append(float(match.group(1)))
            
            # Calculate jitter as average difference between consecutive pings
            if len(ping_times) >= 2:
                differences = [abs(ping_times[i] - ping_times[i-1]) for i in range(1, len(ping_times))]
                return sum(differences) / len(differences)
            
            return None
            
        except Exception:
            return None
    
    def measure_connection_times(self, hosts=None, port=80):
        """
        Measure time to establish TCP connections
        
        Args:
            hosts (list): List of hosts to connect to
            port (int): Port to connect to
        """
        hosts = hosts or [h for h in self.common_destinations if not self._is_ip_address(h)]
        
        for host in hosts:
            try:
                conn_time = self._measure_connection_time(host, port)
                
                with self._lock:
                    if conn_time is not None:
                        self.connection_times[host].append(conn_time)
                        self.historical_metrics['connection_time'][host].append({
                            'timestamp': datetime.datetime.now(),
                            'value': conn_time
                        })
            
            except Exception as e:
                print(f"Error measuring connection time to {host}: {e}")
    
    def _measure_connection_time(self, host, port=80):
        """
        Measure time to establish a TCP connection
        
        Args:
            host (str): Host to connect to
            port (int): Port to connect to
            
        Returns:
            float: Connection time in milliseconds or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            start_time = time.time()
            sock.connect((host, port))
            end_time = time.time()
            
            sock.close()
            
            # Return connection time in milliseconds
            return (end_time - start_time) * 1000
        except Exception:
            # Record a retry attempt
            self.connection_retries[host] += 1
            return None
    
    def get_jitter_metrics(self, host=None):
        """
        Get jitter metrics for specified host or all hosts
        
        Args:
            host (str): Host to get metrics for (None for all)
            
        Returns:
            dict: Jitter metrics
        """
        results = {}
        
        with self._lock:
            hosts = [host] if host else self.jitter.keys()
            
            for h in hosts:
                if h in self.jitter and len(self.jitter[h]) > 0:
                    values = list(self.jitter[h])
                    results[h] = {
                        'current': values[-1],
                        'min': min(values),
                        'max': max(values),
                        'avg': statistics.mean(values),
                        'history': self.historical_metrics['jitter'][h][-10:] if h in self.historical_metrics['jitter'] else []
                    }
        
        return results
    
    def get_connection_time_metrics(self, host=None):
        """
        Get connection time metrics for specified host or all hosts
        
        Args:
            host (str): Host to get metrics for (None for all)
            
        Returns:
            dict: Connection time metrics
        """
        results = {}
        
        with self._lock:
            hosts = [host] if host else self.connection_times.keys()
            
            for h in hosts:
                if h in self.connection_times and len(self.connection_times[h]) > 0:
                    values = list(self.connection_times[h])
                    results[h] = {
                        'current': values[-1],
                        'min': min(values),
                        'max': max(values),
                        'avg': statistics.mean(values),
                        'median': statistics.median(values),
                        'history': self.historical_metrics['connection_time'][h][-10:] if h in self.historical_metrics['connection_time'] else [],
                        'retry_attempts': self.connection_retries[h]
                    }
        
        return results
    
    def get_comprehensive_metrics(self, host=None):
        """
        Get all performance metrics for a host
        
        Args:
            host (str): Host to get metrics for (None for all)
            
        Returns:
            dict: Comprehensive performance metrics
        """
        results = {}
        
        # Gather all metrics
        latency = self.get_latency_metrics(host)
        packet_loss = self.get_packet_loss_metrics(host)
        jitter = self.get_jitter_metrics(host)
        connection_time = self.get_connection_time_metrics(host)
        
        # Combine metrics
        hosts = set()
        for metrics in [latency, packet_loss, jitter, connection_time]:
            hosts.update(metrics.keys())
        
        for h in hosts:
            results[h] = {
                'latency': latency.get(h, {}),
                'packet_loss': packet_loss.get(h, {}),
                'jitter': jitter.get(h, {}),
                'connection_time': connection_time.get(h, {}),
                'retry_attempts': self.connection_retries.get(h, 0)
            }
            
            # Add DNS metrics if applicable
            if not self._is_ip_address(h):
                dns_metrics = self.get_dns_resolution_metrics(h)
                if dns_metrics:
                    results[h]['dns_resolution'] = dns_metrics.get(h, {})
        
        return results
    
    def measure_retries(self, host):
        """
        Get number of retry attempts for a host
        
        Args:
            host (str): Host to check retry attempts for
            
        Returns:
            int: Number of retry attempts
        """
        with self._lock:
            return self.connection_retries.get(host, 0)
            
    def measure_latency(self, hosts=None):
        """
        Measure latency to specified hosts or common destinations
        
        Args:
            hosts (list): List of hosts to ping (None for default destinations)
        """
        hosts = hosts or self.common_destinations
        
        for host in hosts:
            try:
                avg_latency, packet_loss = self._ping_host(host)
                
                with self._lock:
                    if avg_latency is not None:
                        self.latency[host].append(avg_latency)
                        self.historical_metrics['latency'][host].append({
                            'timestamp': datetime.datetime.now(),
                            'value': avg_latency
                        })
                    
                    if packet_loss is not None:
                        self.packet_loss[host].append(packet_loss)
                        self.historical_metrics['packet_loss'][host].append({
                            'timestamp': datetime.datetime.now(),
                            'value': packet_loss
                        })
                        
            except Exception as e:
                print(f"Error measuring latency to {host}: {e}")
    
    def _ping_host(self, host):
        """
        Ping a host and return avg latency and packet loss
        
        Args:
            host (str): Host to ping
            
        Returns:
            tuple: (avg_latency, packet_loss_percentage)
        """
        try:
            # Platform specific ping command
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "4", host]
            else:
                cmd = ["ping", "-c", "4", host]
                
            # Run ping command and capture output
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True, timeout=10)
            
            # Extract latency data
            if platform.system().lower() == "windows":
                # Parse Windows ping output
                match = re.search(r'Average = (\d+)ms', output)
                avg_latency = float(match.group(1)) if match else None
                
                # Look for packet loss information
                match = re.search(r'Lost = (\d+) \((\d+)% loss\)', output)
                packet_loss = float(match.group(2)) if match else None
            else:
                # Parse Unix ping output
                match = re.search(r'min/avg/max/mdev = [\d.]+/([\d.]+)/', output)
                avg_latency = float(match.group(1)) if match else None
                
                # Look for packet loss information
                match = re.search(r'(\d+)% packet loss', output)
                packet_loss = float(match.group(1)) if match else None
                
            return avg_latency, packet_loss
            
        except subprocess.CalledProcessError:
            # Host unreachable - 100% packet loss
            return None, 100.0
        except Exception as e:
            print(f"Error pinging {host}: {e}")
            return None, None
    
    def measure_dns_resolution(self, domains=None):
        """
        Measure DNS resolution times for specified domains or common destinations
        
        Args:
            domains (list): List of domains to measure (None for default destinations)
        """
        domains = domains or [host for host in self.common_destinations if not self._is_ip_address(host)]
        
        for domain in domains:
            try:
                resolution_time = self._measure_dns_resolution_time(domain)
                
                with self._lock:
                    if resolution_time is not None:
                        self.dns_resolution[domain].append(resolution_time)
                        self.historical_metrics['dns_resolution'][domain].append({
                            'timestamp': datetime.datetime.now(),
                            'value': resolution_time
                        })
                        
            except Exception as e:
                print(f"Error measuring DNS resolution time for {domain}: {e}")
    
    def _measure_dns_resolution_time(self, domain):
        """
        Measure DNS resolution time for a domain
        
        Args:
            domain (str): Domain to measure
            
        Returns:
            float: Resolution time in milliseconds or None
        """
        try:
            start_time = time.time()
            socket.gethostbyname(domain)
            end_time = time.time()
            
            # Return resolution time in milliseconds
            return (end_time - start_time) * 1000
        except Exception:
            return None
    
    def _is_ip_address(self, host):
        """
        Check if the host is an IP address
        
        Args:
            host (str): Host to check
            
        Returns:
            bool: True if host is an IP address
        """
        try:
            socket.inet_aton(host)
            return True
        except socket.error:
            return False
    
    def get_latency_metrics(self, host=None):
        """
        Get latency metrics for a host or all hosts
        
        Args:
            host (str): Host to get metrics for (None for all)
            
        Returns:
            dict: Latency metrics
        """
        results = {}
        
        with self._lock:
            hosts = [host] if host else self.latency.keys()
            
            for h in hosts:
                if h in self.latency and len(self.latency[h]) > 0:
                    values = list(self.latency[h])
                    results[h] = {
                        'current': values[-1],
                        'min': min(values),
                        'max': max(values),
                        'avg': statistics.mean(values),
                        'median': statistics.median(values),
                        'history': self.historical_metrics['latency'][h][-10:] if h in self.historical_metrics['latency'] else []
                    }
        
        return results
    
    def get_packet_loss_metrics(self, host=None):
        """
        Get packet loss metrics for a host or all hosts
        
        Args:
            host (str): Host to get metrics for (None for all)
            
        Returns:
            dict: Packet loss metrics
        """
        results = {}
        
        with self._lock:
            hosts = [host] if host else self.packet_loss.keys()
            
            for h in hosts:
                if h in self.packet_loss and len(self.packet_loss[h]) > 0:
                    values = list(self.packet_loss[h])
                    results[h] = {
                        'current': values[-1],
                        'min': min(values),
                        'max': max(values),
                        'avg': statistics.mean(values),
                        'history': self.historical_metrics['packet_loss'][h][-10:] if h in self.historical_metrics['packet_loss'] else []
                    }
        
        return results
    
    def get_dns_resolution_metrics(self, domain=None):
        """
        Get DNS resolution metrics for a domain or all domains
        
        Args:
            domain (str): Domain to get metrics for (None for all)
            
        Returns:
            dict: DNS resolution metrics
        """
        results = {}
        
        with self._lock:
            domains = [domain] if domain else self.dns_resolution.keys()
            
            for d in domains:
                if d in self.dns_resolution and len(self.dns_resolution[d]) > 0:
                    values = list(self.dns_resolution[d])
                    results[d] = {
                        'current': values[-1],
                        'min': min(values),
                        'max': max(values),
                        'avg': statistics.mean(values),
                        'median': statistics.median(values),
                        'history': self.historical_metrics['dns_resolution'][d][-10:] if d in self.historical_metrics['dns_resolution'] else []
                    }
        
        return results
    
    def add_monitoring_target(self, host):
        """
        Add a new host to monitor
        
        Args:
            host (str): Host to monitor
        """
        if host not in self.common_destinations:
            self.common_destinations.append(host)
