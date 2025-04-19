import os
import time
import signal
import sys
from network_scanner import NetworkScanner
from traffic_analyzer import TrafficAnalyzer
from performance_monitor import PerformanceMonitor
from network_metrics_manager import NetworkMetricsManager
from config import (
    NETWORK_RANGE,
    SCAN_INTERVAL,
    PERFORMANCE_INTERVAL,
    DEFAULT_MONITORING_TARGETS,
    DATA_DIR,
    TRAFFIC_CSV
)

def signal_handler(sig, frame):
    """Handle Ctrl+C to gracefully shutdown the application"""
    print("\nShutting down NetVision...")
    if metrics_manager:
        metrics_manager.stop()
    sys.exit(0)

def ensure_data_directory():
    """Create data directory if it doesn't exist"""
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), DATA_DIR)
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    return data_dir

def main():
    global metrics_manager
    
    print("Starting NetVision Network Monitoring Tool...")
    print(f"Monitoring network: {NETWORK_RANGE}")
    
    # Ensure data directory exists
    data_dir = ensure_data_directory()
    csv_path = os.path.join(data_dir, TRAFFIC_CSV)
    
    # Initialize components
    print("Initializing components...")
    scanner = NetworkScanner(network=NETWORK_RANGE, scan_interval=SCAN_INTERVAL)
    analyzer = TrafficAnalyzer(network_scanner=scanner, csv_path=csv_path)
    monitor = PerformanceMonitor(interval=PERFORMANCE_INTERVAL)
    
    # Create and start the metrics manager
    metrics_manager = NetworkMetricsManager(
        network_scanner=scanner,
        traffic_analyzer=analyzer,
        performance_monitor=monitor
    )
    
    # Start monitoring
    print("Starting network monitoring...")
    metrics_manager.start()
    
    # Add monitoring targets
    print("Adding monitoring targets...")
    for site in DEFAULT_MONITORING_TARGETS:
        metrics_manager.add_performance_target(site)
    
    # Main loop - print some stats periodically
    try:
        while True:
            time.sleep(30)  # Wait for 30 seconds
            
            # Get current metrics
            bandwidth = metrics_manager.get_metrics("bandwidth")
            devices = metrics_manager.get_metrics("devices")
            
            # Print some basic info
            print("\n--- NetVision Status Update ---")
            print(f"Active devices: {len(devices)}")
            print("Current bandwidth usage:")
            
            for ip, data in bandwidth.items():
                print(f"  {ip}: ↑ {data.get('upload', 0):.2f} KB/s | ↓ {data.get('download', 0):.2f} KB/s")
                
            # Print performance metrics for one destination
            if monitor.common_destinations:
                target = monitor.common_destinations[0]
                perf = monitor.get_comprehensive_metrics(target)
                if target in perf:
                    print(f"\nPerformance metrics for {target}:")
                    if 'latency' in perf[target] and perf[target]['latency']:
                        print(f"  Latency: {perf[target]['latency'].get('avg', 0):.2f} ms")
                    if 'packet_loss' in perf[target] and perf[target]['packet_loss']:
                        print(f"  Packet loss: {perf[target]['packet_loss'].get('avg', 0):.2f}%")
            
            print("--------------------------------")
            
    except KeyboardInterrupt:
        pass
    finally:
        # Stop all monitoring
        if metrics_manager:
            print("Stopping monitoring services...")
            metrics_manager.stop()
            
    print("NetVision has been shut down.")

if __name__ == "__main__":
    # Setup signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Global metrics manager
    metrics_manager = None
    
    # Run main function
    main()
