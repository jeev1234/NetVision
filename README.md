# NetVision

NetVision is a comprehensive network monitoring and traffic analysis tool that provides real-time visibility into your local network. It captures and analyzes network packets, displays protocol distribution, identifies active devices, and helps identify potential network issues.

## Features

- **Network Traffic Monitoring**: Captures and logs network packets in real-time
- **Protocol Analysis**: Visualizes the distribution of network protocols (TCP, UDP, etc.)
- **Device Discovery**: Scans and identifies all active devices on your network
- **Top Talkers**: Identifies the most active IP addresses on your network
- **Interactive Dashboard**: Web-based visualization with real-time data updates

## Requirements

- Python 3.8+
- Nmap (for network scanning)
- Admin/root privileges (for packet capturing)

## Installation

```bash
# Clone the repository and navigate to the project directory
cd NetVision

# Create and activate virtual environment
python -m venv nv
source nv/bin/activate  # On Linux/Mac
# or
nv\Scripts\activate  # On Windows

# Install dependencies
pip install -r requirements.txt

# Create data directory if it doesn't exist
mkdir -p data
```