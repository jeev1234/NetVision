import nmap

def scan_network(network='10.14.146.0/23'):
    """
    Scan local network and return list of active devices
    
    Args:
        network (str): Network range to scan (default: 10.14.146.0/23)
    
    Returns:
        list: Discovered devices with IP and MAC
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    
    devices = []
    for host in nm.all_hosts():
        try:
            mac = nm[host]['addresses'].get('mac', 'Unknown')
            hostname = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else 'Unknown'
            
            device_info = {
                'ip': host,
                'mac': mac,
                'hostname': hostname
            }
            devices.append(device_info)
        except Exception as e:
            print(f"Error scanning {host}: {e}")
    
    return devices