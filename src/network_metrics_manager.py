import threading
import datetime
from collections import defaultdict
import ipaddress
import time

class NetworkMetricsManager:
    """
    Central class that aggregates metrics from all monitoring components
    and provides unified access to network metrics data.
    """
    
    def __init__(self, network_scanner=None, traffic_analyzer=None, performance_monitor=None):
        """
        Initialize the NetworkMetricsManager
        
        Args:
            network_scanner: NetworkScanner instance
            traffic_analyzer: TrafficAnalyzer instance
            performance_monitor: PerformanceMonitor instance
        """
        self.network_scanner = network_scanner
        self.traffic_analyzer = traffic_analyzer
        self.performance_monitor = performance_monitor
        self._lock = threading.Lock()
        self.aggregated_metrics = {}
        self.last_update = defaultdict(lambda: datetime.datetime.min)
        self.update_intervals = {
            'device_metrics': 60,     # Update device metrics every 60 seconds
            'traffic_metrics': 30,    # Update traffic metrics every 30 seconds
            'performance_metrics': 60, # Update performance metrics every 60 seconds
            'bandwidth_metrics': 5,   # Update bandwidth metrics every 5 seconds
        }
    
    def start(self):
        """Start the metrics collection from all components"""
        # Start individual components if they exist
        if self.network_scanner:
            self.network_scanner.start_continuous_scanning()
        
        if self.traffic_analyzer:
            self.traffic_analyzer.start_capture()
        
        if self.performance_monitor:
            self.performance_monitor.start_monitoring()
        
        # Start metrics aggregation thread
        threading.Thread(target=self._aggregation_loop, daemon=True).start()
    
    def stop(self):
        """Stop metrics collection from all components"""
        if self.network_scanner:
            self.network_scanner.stop_continuous_scanning()
        
        if self.traffic_analyzer:
            self.traffic_analyzer.stop_capture()
        
        if self.performance_monitor:
            self.performance_monitor.stop_monitoring()
    
    def _aggregation_loop(self):
        """Background thread that periodically aggregates metrics"""
        while True:
            try:
                current_time = datetime.datetime.now()
                
                # Update device metrics if interval has passed
                if (current_time - self.last_update['device_metrics']).total_seconds() >= self.update_intervals['device_metrics']:
                    self._update_device_metrics()
                    self.last_update['device_metrics'] = current_time
                
                # Update traffic metrics if interval has passed
                if (current_time - self.last_update['traffic_metrics']).total_seconds() >= self.update_intervals['traffic_metrics']:
                    self._update_traffic_metrics()
                    self.last_update['traffic_metrics'] = current_time
                
                # Update performance metrics if interval has passed
                if (current_time - self.last_update['performance_metrics']).total_seconds() >= self.update_intervals['performance_metrics']:
                    self._update_performance_metrics()
                    self.last_update['performance_metrics'] = current_time
                
                # Update bandwidth metrics more frequently
                if (current_time - self.last_update['bandwidth_metrics']).total_seconds() >= self.update_intervals['bandwidth_metrics']:
                    self._update_bandwidth_metrics()
                    self.last_update['bandwidth_metrics'] = current_time
                
                # Sleep a short time before checking again
                time.sleep(1)
                
            except Exception as e:
                print(f"Error in metrics aggregation: {e}")
                time.sleep(5)  # Sleep longer on error
    
    def _update_device_metrics(self):
        """Update device-level metrics"""
        if not self.network_scanner:
            return
        
        with self._lock:
            self.aggregated_metrics['devices'] = self.network_scanner.get_device_metrics()
            
            # Update device bandwidth metrics if traffic analyzer is available
            if self.traffic_analyzer and hasattr(self.traffic_analyzer, 'update_device_bandwidth_metrics'):
                self.traffic_analyzer.update_device_bandwidth_metrics(self.network_scanner)
    
    def _update_traffic_metrics(self):
        """Update traffic analysis metrics"""
        if not self.traffic_analyzer:
            return
        
        with self._lock:
            try:
                # Get protocol distribution from actual captured data
                self.aggregated_metrics['protocol_distribution'] = self.traffic_analyzer.get_protocol_distribution()
                
                # Get recent connections from actual captured data
                if hasattr(self.traffic_analyzer, 'get_connection_stats') and hasattr(self.traffic_analyzer, 'connection_history'):
                    self.aggregated_metrics['recent_connections'] = self.traffic_analyzer.get_connection_stats(limit=50)
                else:
                    self.aggregated_metrics['recent_connections'] = []
                
                # Add check to ensure only real connections are kept
                if 'recent_connections' in self.aggregated_metrics:
                    # Filter out any potentially simulated connections
                    real_connections = []
                    for conn in self.aggregated_metrics['recent_connections']:
                        if conn.get('src_ip') and conn.get('dst_ip'):  # Ensure basic data exists
                            real_connections.append(conn)
                    self.aggregated_metrics['recent_connections'] = real_connections
                
                # Clean up stale UDP connections
                if hasattr(self.traffic_analyzer, 'cleanup_stale_connections'):
                    self.traffic_analyzer.cleanup_stale_connections()
            except Exception as e:
                print(f"Error updating traffic metrics: {e}")
    
    def _update_performance_metrics(self):
        """Update network performance metrics"""
        if not self.performance_monitor:
            return
        
        with self._lock:
            self.aggregated_metrics['performance'] = self.performance_monitor.get_comprehensive_metrics()
    
    def _update_bandwidth_metrics(self):
        """Update real-time bandwidth metrics"""
        if not self.traffic_analyzer:
            return
        
        with self._lock:
            self.aggregated_metrics['bandwidth'] = self.traffic_analyzer.get_bandwidth_metrics(interval=5)
    
    def get_metrics(self, metric_type=None):
        """
        Get aggregated metrics
        
        Args:
            metric_type (str): Type of metrics to return (None for all)
            
        Returns:
            dict: Requested metrics
        """
        with self._lock:
            if metric_type:
                return self.aggregated_metrics.get(metric_type, {})
            else:
                return self.aggregated_metrics
    
    def get_device_details(self, ip):
        """
        Get comprehensive details for a specific device
        
        Args:
            ip (str): IP address of the device
            
        Returns:
            dict: Device details including all metrics
        """
        result = {}
        
        with self._lock:
            # Basic device info from scanner
            if self.network_scanner and 'devices' in self.aggregated_metrics:
                device_metrics = self.aggregated_metrics['devices'].get(ip, {})
                if device_metrics:
                    result.update(device_metrics)
            
            # Bandwidth metrics
            if 'bandwidth' in self.aggregated_metrics:
                bandwidth = self.aggregated_metrics['bandwidth'].get(ip, {})
                if bandwidth:
                    result['real_time_bandwidth'] = bandwidth
            
            # Filter connections for this IP
            if 'recent_connections' in self.aggregated_metrics:
                device_connections = [
                    conn for conn in self.aggregated_metrics['recent_connections']
                    if conn['src_ip'] == ip or conn['dst_ip'] == ip
                ]
                result['recent_connections'] = device_connections[:10]  # Top 10
        
        return result
    
    def add_performance_target(self, target):
        """
        Add a new target for performance monitoring
        
        Args:
            target (str): IP address or hostname to monitor
        """
        if self.performance_monitor:
            self.performance_monitor.add_monitoring_target(target)
            
            # Force immediate measurement
            try:
                self.performance_monitor.measure_latency([target])
                
                if not self.performance_monitor._is_ip_address(target):
                    self.performance_monitor.measure_dns_resolution([target])
            except:
                pass
