# NetVision

NetVision is a comprehensive network monitoring and traffic analysis tool that provides real-time visibility into your local network. It captures and analyzes network packets, displays protocol distribution, identifies active devices, and helps identify potential network issues.

## Features

- **Network Traffic Monitoring**: Captures and logs network packets in real-time
- **Protocol Analysis**: Visualizes the distribution of network protocols (TCP, UDP, etc.)
- **Device Discovery**: Scans and identifies all active devices on your network
- **Top Talkers**: Identifies the most active IP addresses on your network
- **Interactive Dashboard**: Web-based visualization with real-time data updates

## Prerequisites

- **Python 3.8+**
- **Nmap** installed on your system (required for network scanning)
  - Ubuntu/Debian: `sudo apt-get install nmap`
  - Fedora/RHEL: `sudo dnf install nmap`
  - macOS: `brew install nmap`
  - Windows: Download from https://nmap.org/download.html
- **Admin/root privileges** (required for packet capturing)

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

## Usage

The application requires administrator/root privileges to capture network packets:

```bash
# Make sure you're in the project directory with the virtual environment activated
cd /path/to/NetVision
source nv/bin/activate

# Run the application with admin/root privileges
# On Linux/Mac:
sudo $(which python) src/app.py

# On Windows (run PowerShell or CMD as Administrator):
python src/app.py
```

After starting the application, open your web browser and navigate to:
```
http://127.0.0.1:5000
```