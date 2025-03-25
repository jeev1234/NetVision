from flask import Flask, render_template, jsonify
from network_scanner import scan_network
from packet_capture import PacketCapturer
from traffic_analyzer import TrafficAnalyzer
import os

# Ensure data directory exists
os.makedirs('../data', exist_ok=True)

app = Flask(__name__, 
            static_folder='../static', 
            template_folder='../templates')

@app.route('/')
def dashboard():
    """Render main dashboard"""
    # Use absolute path for CSV file
    csv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data/network_traffic.csv')
    analyzer = TrafficAnalyzer(csv_path=csv_path)
    protocol_chart = analyzer.generate_protocol_pie_chart()
    return render_template('dashboard.html', protocol_chart=protocol_chart)

@app.route('/api/devices')
def get_devices():
    """API endpoint for discovered devices"""
    devices = scan_network()
    return jsonify(devices)

@app.route('/api/traffic_analysis')
def get_traffic_analysis():
    """API endpoint for traffic analysis"""
    csv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data/network_traffic.csv')
    analyzer = TrafficAnalyzer(csv_path=csv_path)
    protocol_dist = analyzer.protocol_distribution()
    top_talkers = analyzer.top_talkers()
    
    return jsonify({
        'protocol_distribution': protocol_dist.to_dict() if not protocol_dist.empty else {},
        'top_talkers': top_talkers.to_dict() if not top_talkers.empty else {}
    })

def start_packet_capture(duration=60):
    """Background packet capture"""
    # Use absolute path for CSV file
    csv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data/network_traffic.csv')
    capturer = PacketCapturer(csv_path=csv_path)
    capturer.start_capture(duration)

if __name__ == '__main__':
    # Optional: Start packet capture in background
    import threading
    capture_thread = threading.Thread(target=start_packet_capture)
    capture_thread.start()
    
    app.run(debug=True)