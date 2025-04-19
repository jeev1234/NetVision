import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
import os
from collections import defaultdict
import time
import datetime
import threading
import random

class TrafficAnalyzer:
    def __init__(self, csv_path='data/network_traffic.csv', network_scanner=None):
        self.csv_path = csv_path
        self.network_scanner = network_scanner
        # Create empty DataFrame with required columns if file doesn't exist
        if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
            self.df = pd.DataFrame(columns=[
                'timestamp', 'source_ip', 'destination_ip', 
                'source_port', 'destination_port', 
                'protocol', 'packet_length'
            ])
        else:
            try:
                self.df = pd.read_csv(csv_path)
                print(f"Loaded {len(self.df)} traffic records")
            except Exception as e:
                print(f"Error loading traffic data: {e}")
                self.df = pd.DataFrame(columns=[
                    'timestamp', 'source_ip', 'destination_ip', 
                    'source_port', 'destination_port', 
                    'protocol', 'packet_length'
                ])
                
        # Track active connections
        self.active_connections = {}
        # Connection history
        self.connection_history = []
        # Track if capturing
        self._capturing = False
    
    def protocol_distribution(self):
        """Analyze protocol distribution"""
        if self.df.empty:
            # Return empty series if no data
            return pd.Series(dtype='int64')
        return self.df['protocol'].value_counts()
    
    def top_talkers(self, top_n=5):
        """Find top network talkers"""
        if self.df.empty:
            # Return empty series if no data
            return pd.Series(dtype='int64')
        source_counts = self.df['source_ip'].value_counts()
        return source_counts.head(top_n)
    
    def generate_protocol_pie_chart(self):
        """Generate interactive pie chart for protocol distribution"""
        proto_dist = self.protocol_distribution()
        if proto_dist.empty:
            # Create an empty figure with a message if no data
            fig = go.Figure()
            fig.add_annotation(
                text="No network data captured yet. Start capturing packets to see protocol distribution.",
                showarrow=False,
                font=dict(size=14)
            )
            return fig.to_html(full_html=False)
        
        fig = px.pie(
            values=proto_dist.values, 
            names=proto_dist.index, 
            title='Network Protocol Distribution'
        )
        return fig.to_html(full_html=False)
    
    def get_top_talkers(self, limit=10):
        """
        Get top network talkers (highest data transfer)
        
        Args:
            limit (int): Maximum number of results to return
            
        Returns:
            list: Top talkers with their data usage
        """
        if self.df.empty:
            return []
            
        # Group by source IP and sum packet lengths
        source_bytes = self.df.groupby('source_ip')['packet_length'].sum().reset_index()
        source_bytes.columns = ['ip', 'total_bytes']
        
        # Group by destination IP and sum packet lengths
        dest_bytes = self.df.groupby('destination_ip')['packet_length'].sum().reset_index()
        dest_bytes.columns = ['ip', 'total_bytes']
        
        # Combine source and destination data
        combined = pd.concat([source_bytes, dest_bytes])
        
        # Group by IP and sum the bytes
        result = combined.groupby('ip')['total_bytes'].sum().reset_index()
        
        # Sort by total bytes in descending order and take the top limit
        result = result.sort_values('total_bytes', ascending=False).head(limit)
        
        # Convert to list of dicts
        return result.to_dict('records')
    
    def get_bandwidth_metrics(self, interval=5):
        """
        Get bandwidth usage metrics for each IP
        
        Args:
            interval (int): Time interval in seconds to calculate bandwidth
            
        Returns:
            dict: Bandwidth metrics per IP
        """
        try:
            if self.df.empty:
                return {}
                
            # Get recent data based on interval
            recent_df = self.df.tail(1000)  # Take last 1000 rows for efficiency
            
            # Calculate bandwidth metrics
            metrics = {}
            
            # Group by source IP
            source_grouped = recent_df.groupby('source_ip')
            for ip, group in source_grouped:
                if ip not in metrics:
                    metrics[ip] = {'upload': 0, 'download': 0}
                
                # Calculate bytes per second (upload)
                total_bytes = group['packet_length'].sum()
                bytes_per_sec = total_bytes / interval
                metrics[ip]['upload'] = bytes_per_sec / 1024  # Convert to KB/s
            
            # Group by destination IP
            dest_grouped = recent_df.groupby('destination_ip')
            for ip, group in dest_grouped:
                if ip not in metrics:
                    metrics[ip] = {'upload': 0, 'download': 0}
                
                # Calculate bytes per second (download)
                total_bytes = group['packet_length'].sum()
                bytes_per_sec = total_bytes / interval
                metrics[ip]['download'] = bytes_per_sec / 1024  # Convert to KB/s
            
            return metrics
        except Exception as e:
            print(f"Error calculating bandwidth metrics: {e}")
            # Return empty dict since we're not using simulation
            return {}
    
    def get_protocol_distribution(self):
        """
        Get distribution of transport and application protocols
        
        Returns:
            dict: Protocol distribution statistics
        """
        if self.df.empty:
            return {'transport_protocols': {}, 'application_protocols': {}}
        
        # Count transport protocols from actual data
        transport_protocols = self.df['protocol'].value_counts(normalize=True) * 100
        
        # Extract application protocols from actual data
        # This is a simplification - in a real scenario, this would use 
        # deep packet inspection or port analysis
        app_protocols = {}
        try:
            # Group by destination port to estimate application protocols
            port_counts = self.df['destination_port'].value_counts(normalize=True) * 100
            
            # Map common ports to protocols
            common_ports = {
                80: 'HTTP',
                443: 'HTTPS',
                53: 'DNS',
                25: 'SMTP',
                110: 'POP3',
                143: 'IMAP',
                21: 'FTP',
                22: 'SSH',
                3306: 'MySQL',
                5432: 'PostgreSQL'
            }
            
            for port, percentage in port_counts.items():
                if port in common_ports:
                    app_name = common_ports[port]
                    app_protocols[app_name] = percentage
                else:
                    app_protocols.setdefault('Other', 0)
                    app_protocols['Other'] += percentage
        except Exception as e:
            print(f"Error analyzing application protocols: {e}")
            
        return {
            'transport_protocols': transport_protocols.to_dict(),
            'application_protocols': app_protocols
        }
    
    def get_connection_stats(self, limit=50):
        """
        Get recent connection statistics
        
        Args:
            limit: Maximum number of connections to return
            
        Returns:
            list: Recent connection information
        """
        # Return most recent connections
        return self.connection_history[:limit]
    
    def cleanup_stale_connections(self, timeout=30):
        """
        Remove stale connections from active_connections
        
        Args:
            timeout: Time in seconds after which a connection is considered stale
        """
        current_time = time.time()
        stale_connections = []
        
        # Find stale connections
        for conn_id, conn in self.active_connections.items():
            if current_time - conn['last_updated'] > timeout:
                stale_connections.append(conn_id)
                
                # Create a closed connection record
                conn_record = {
                    'src_ip': conn['src_ip'],
                    'dst_ip': conn['dst_ip'],
                    'src_port': conn['src_port'],
                    'dst_port': conn['dst_port'],
                    'protocol': conn['protocol'],
                    'app_protocol': conn.get('app_protocol', 'Unknown'),
                    'start_time': conn['start_time'],
                    'end_time': current_time,
                    'duration': current_time - conn['start_time'],
                    'bytes_sent': conn.get('bytes_sent', 0),
                    'bytes_received': conn.get('bytes_received', 0),
                    'state': 'timed_out'
                }
                self.connection_history.insert(0, conn_record)
                self.active_connections.pop(conn_id, None)
    
    def start_capture(self):
        """Start traffic capture"""
        if self._capturing:
            return
        print("Traffic analysis started")
        self._capturing = True
        # For demo purposes, let's simulate some data
        # In a real implementation, this would start actual packet capture
        threading.Thread(target=self._simulate_traffic, daemon=True).start()
    
    def _simulate_traffic(self):
        """Simulate traffic data for demonstration"""
        while self._capturing:
            # Generate some random connections for demo purposes
            # In a real implementation, this would process actual network traffic
            time.sleep(1)
    
    def stop_capture(self):
        """Stop traffic capture"""
        self._capturing = False
        print("Traffic analysis stopped")
    
    def update_device_bandwidth_metrics(self, network_scanner=None):
        """
        Update bandwidth metrics for devices tracked by the network scanner
        
        Args:
            network_scanner: The NetworkScanner instance to update
        """
        if not network_scanner or not hasattr(network_scanner, 'devices'):
            return
        
        # Get actual bandwidth metrics from captured data
        bandwidth_metrics = self.get_bandwidth_metrics()
        
        # Get protocol distribution from actual data
        protocol_dist = self.get_protocol_distribution()
        
        # Update metrics for each device with actual data only
        with network_scanner._lock:
            for ip, device_data in network_scanner.devices.items():
                # Update bandwidth usage only if we have real data
                if ip in bandwidth_metrics:
                    # Calculate actual sent and received bytes
                    sent_bytes = 0
                    received_bytes = 0
                    
                    # Calculate based on actual traffic data
                    if not self.df.empty:
                        # Find packets sent from this IP
                        sent_data = self.df[self.df['source_ip'] == ip]
                        if not sent_data.empty:
                            sent_bytes = sent_data['packet_length'].sum()
                        
                        # Find packets received by this IP
                        received_data = self.df[self.df['destination_ip'] == ip]
                        if not received_data.empty:
                            received_bytes = received_data['packet_length'].sum()
                    
                    # Update device data with real captured values
                    device_data['bandwidth_usage'] = {
                        'total_sent_bytes': sent_bytes,
                        'total_received_bytes': received_bytes
                    }
                
                # Update protocol distribution only if we have real data
                if not self.df.empty:
                    # Get device specific protocol stats
                    device_protocols = {}
                    device_packets = self.df[(self.df['source_ip'] == ip) | (self.df['destination_ip'] == ip)]
                    
                    if not device_packets.empty:
                        proto_counts = device_packets['protocol'].value_counts(normalize=True) * 100
                        device_data['protocol_distribution'] = proto_counts.to_dict()