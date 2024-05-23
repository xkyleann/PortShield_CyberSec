# Example IP Address: 192.168.1.1  
# Start Port: 1 
# End Port: 100 
import socket
import threading
import ipaddress

# Dictionary to store vulnerable services and their descriptions
vulnerable_services = {
    "ftp": "Known vulnerabilities in FTP service.",
    "ssh": "Potential weak passwords in SSH service.",
    "telnet": "Telnet is insecure and should not be used.",
    "http": "Check for outdated web servers or known exploits.",
    "https": "Check for SSL/TLS vulnerabilities.",
}

def scan_port(ip, port, open_ports, vulnerabilities):
    """
    Function to scan a single port and identify the service
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)  # Set timeout to 1 second  # Acceptance Criteria 2
        if sock.connect_ex((ip, port)) == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            open_ports.append((port, service))
            print(f"Port {port} is open and running {service}.")  # Acceptance Criteria 4
            if service in vulnerable_services:
                vulnerabilities.append((port, service, vulnerable_services[service]))  # Acceptance Criteria 5

def scan_ports_concurrently(ip, start_port, end_port):
    """
    Function to scan a range of ports concurrently
    """
    open_ports = []
    vulnerabilities = []
    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(ip, port, open_ports, vulnerabilities))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return open_ports, vulnerabilities

if __name__ == "__main__":
    # user input for IP address and port range
    ip = input("Enter IP address to scan: ")  # Acceptance Criteria 1
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print("Invalid IP address.")  # Acceptance Criteria 1
        exit()

    start_port = int(input("Enter start port: "))  # Acceptance Criteria 1
    end_port = int(input("Enter end port: "))  # Acceptance Criteria 1

    # initiating port scanning process
    print(f"Scanning {ip} from port {start_port} to {end_port}...")  # Acceptance Criteria 1
    open_ports, vulnerabilities = scan_ports_concurrently(ip, start_port, end_port)

    # displaying scan results
    if open_ports:
        print(f"Open ports: {[(port, service) for port, service in open_ports]}")  # Acceptance Criteria 4
    else:
        print("No open ports found.")  # Acceptance Criteria 4

    if vulnerabilities:
        print("Vulnerabilities found:")  # Acceptance Criteria 5
        for port, service, vulnerability in vulnerabilities:
            print(f"Port {port} (service: {service}) - {vulnerability}")  # Acceptance Criteria 5
    else:
        print("No known vulnerabilities found.")  # Acceptance Criteria 5
