# NetVision

NetVision is a comprehensive network monitoring and traffic analysis tool that provides real-time visibility into your local network. It captures and analyzes network packets, displays protocol distribution, identifies active devices, and helps identify potential network issues.

## Features

- **Network Traffic Monitoring**: Captures and logs network packets in real-time.
- **Protocol Analysis**: Visualizes the distribution of network protocols (TCP, UDP, etc.).
- **Device Discovery**: Scans and identifies all active devices on your network.
- **Top Talkers**: Identifies the most active IP addresses on your network.
- **Interactive Dashboard**: Web-based visualization with real-time data updates.
- **Performance Monitoring**: 
  - Latency measurement.
  - Packet loss detection.
  - Network jitter calculation.
  - DNS resolution time.
  - Connection establishment time.
- **Bandwidth Analysis**: Monitors upload/download rates for each device.
- **Connection Tracking**: Records connection durations, frequencies, and patterns.
- **Comprehensive Metrics**: Includes connection statistics, history, and performance indicators.

## Prerequisites

- **Python 3.8+**
- **Nmap** installed on your system (required for network scanning):
  - Ubuntu/Debian: `sudo apt-get install nmap`
  - Fedora/RHEL: `sudo dnf install nmap`
  - macOS: `brew install nmap`
  - Windows: Download from https://nmap.org/download.html
- **Admin/root privileges** (required for packet capturing).

## Installation

1. Clone this repository and cd into the Netvision directory:
   
2. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

   Or use a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Linux/Mac
   venv\Scripts\activate     # On Windows
   pip install -r requirements.txt
   ```

## Usage

Run the dashboard application with admin/root privileges:

```bash
# If using the system Python installation:
sudo python3 src/dashboard.py

# If using a virtual environment on Linux/Mac:
sudo $(which python) src/dashboard.py

# On Windows (run Command Prompt or PowerShell as Administrator):
python src/dashboard.py
```

The application will:
- Scan your network for active devices.
- Start monitoring network traffic.
- Begin collecting performance metrics.
- Display real-time updates in the dashboard.

Press `Ctrl+C` to stop the application.

Then open your web browser and navigate to:
```
http://localhost:8050
```

The dashboard provides:
- Active device list and top talkers.
- Real-time bandwidth usage graphs.
- Protocol distribution charts.
- Connection statistics and history.
- Comprehensive performance metrics:
  - Network latency.
  - Packet loss.
  - Network jitter.
  - DNS resolution times.
  - Connection establishment times.

## Configuration

Modify the `NETWORK_RANGE` variable in `src/config.py` to match your local network:

```python
NETWORK_RANGE = "192.168.1.0/24"  # Change to match your network
```

Common network ranges:
- "192.168.0.0/24" or "192.168.1.0/24" for most home networks.
- "10.0.0.0/24" for some ISP-provided routers.
- "172.16.0.0/16" for certain corporate networks.