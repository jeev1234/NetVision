import csv
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

class PacketCapturer:
    def __init__(self, csv_path='data/network_traffic.csv'):
        self.csv_path = csv_path
        self.initialize_csv()
    
    def initialize_csv(self):
        """Create CSV with headers if it doesn't exist"""
        with open(self.csv_path, 'a', newline='') as file:
            writer = csv.writer(file)
            file.seek(0, 2)  # Move to end of file
            if file.tell() == 0:
                writer.writerow([
                    'timestamp', 'source_ip', 'destination_ip', 
                    'source_port', 'destination_port', 
                    'protocol', 'packet_length'
                ])
    
    def packet_handler(self, packet):
        """Process and log each captured packet"""
        if IP in packet:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Determine protocol and ports
            if TCP in packet:
                protocol = 'TCP'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = 'UDP'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                protocol = 'Other'
                src_port = dst_port = 0
            
            # Log packet to CSV
            with open(self.csv_path, 'a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([
                    timestamp, src_ip, dst_ip, 
                    src_port, dst_port, 
                    protocol, len(packet)
                ])
    
    def start_capture(self, duration=60, filter_str=None):
        """
        Start packet capture
        
        Args:
            duration (int): Capture duration in seconds
            filter_str (str): Optional packet filter
        """
        print(f"Starting packet capture for {duration} seconds...")
        sniff(
            prn=self.packet_handler, 
            timeout=duration, 
            filter=filter_str
        )