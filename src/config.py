"""
NetVision Configuration File

This file contains all configurable settings for the NetVision application.
Modify the values here to customize the application behavior.
"""

# Network Configuration
# Change this to match your network (examples: "192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/16")
NETWORK_RANGE = "10.14.146.81/23"  # Using your network from the error message

# Monitoring Configuration
SCAN_INTERVAL = 300  # How often to scan for devices (in seconds)
PERFORMANCE_INTERVAL = 60  # How often to measure performance metrics (in seconds)
METRICS_RETENTION = 100  # How many historical metrics to keep per target

# Dashboard Configuration
DASHBOARD_UPDATE_INTERVAL = 5000  # Dashboard update interval (in milliseconds)
DASHBOARD_HOST = "127.0.0.1"  # Dashboard server host
DASHBOARD_PORT = 8050  # Dashboard server port

# Default Performance Monitoring Targets
DEFAULT_MONITORING_TARGETS = [
    "google.com",
    "amazon.com",
    "cloudflare.com",
    "github.com",
    "8.8.8.8",  # Google DNS
    "1.1.1.1"   # Cloudflare DNS
]

# File Paths
DATA_DIR = "data"
TRAFFIC_CSV = "network_traffic.csv"

# Packet Capture Configuration
CAPTURE_BUFFER_SIZE = 65535  # Maximum packet capture buffer size
MAX_PACKETS_STORED = 10000   # Maximum number of packets to keep in memory
