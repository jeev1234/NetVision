import nmap
import time
import threading
import os
import sys
from collections import defaultdict

# Add parent directory to path to import config
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

try:
    from src.config import NETWORK_RANGE, SCAN_INTERVAL
except ImportError:
    # Fallback to default values if config not available
    NETWORK_RANGE = "192.168.1.0/24"
    SCAN_INTERVAL = 300

class NetworkScanner:
    def __init__(self, network=None, scan_interval=None):
        """
        Initialize Network Scanner
        
        Args:
            network (str): Network range to scan
            scan_interval (int): Interval between scans in seconds
        """
        self.network = network or NETWORK_RANGE
        self.scan_interval = scan_interval or SCAN_INTERVAL
        self._scanning = False
        self._lock = threading.Lock()
        self.devices = {}  # Format: {ip: {mac: str, hostname: str, last_seen: timestamp}}
        
    def scan_network(self):
        """
        Scan the network for active devices
        
        Returns:
            list: Discovered devices
        """
        print(f"Scanning network: {self.network}")
        nm = nmap.PortScanner()
        nm.scan(hosts=self.network, arguments='-sn')
        
        devices = []
        for host in nm.all_hosts():
            try:
                mac = nm[host]['addresses'].get('mac', 'Unknown')
                hostname = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else 'Unknown'
                
                device_info = {
                    'ip': host,
                    'mac': mac,
                    'hostname': hostname,
                    'last_seen': time.time()
                }
                devices.append(device_info)
                
                # Update internal device dictionary
                with self._lock:
                    if host in self.devices:
                        # Update existing device
                        self.devices[host].update(device_info)
                    else:
                        # New device found
                        self.devices[host] = {
                            'mac': mac,
                            'hostname': hostname,
                            'last_seen': time.time(),
                            'first_seen': time.time(),
                            'bandwidth_usage': {
                                'total_sent_bytes': 0,
                                'total_received_bytes': 0
                            },
                            'protocol_distribution': defaultdict(int),
                            'connections': []
                        }
                        
            except Exception as e:
                print(f"Error scanning {host}: {e}")
        
        return devices
        
    def start_continuous_scanning(self):
        """Start continuous network scanning in background thread"""
        if self._scanning:
            return
            
        self._scanning = True
        threading.Thread(target=self._scan_loop, daemon=True).start()
        print(f"Network scanner started (scanning {self.network} every {self.scan_interval} seconds)")
    
    def stop_continuous_scanning(self):
        """Stop the continuous scanning thread"""
        self._scanning = False
        print("Network scanner stopped")
    
    def _scan_loop(self):
        """Internal method for continuous scanning"""
        while self._scanning:
            try:
                self.scan_network()
                time.sleep(self.scan_interval)
            except Exception as e:
                print(f"Error in scan loop: {e}")
                time.sleep(10)  # Sleep longer on error
    
    def get_device_metrics(self):
        """
        Get metrics for all known devices
        
        Returns:
            dict: Device metrics
        """
        with self._lock:
            # Return a copy of device data to prevent modification
            return {ip: device.copy() for ip, device in self.devices.items()}
    
    def get_device_count(self):
        """
        Get count of known devices
        
        Returns:
            int: Number of devices
        """
        with self._lock:
            return len(self.devices)