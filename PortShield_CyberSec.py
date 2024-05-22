import socket
import threading
import ipaddress

# Mock database of known vulnerable services
vulnerable_services = {
    "ftp": "Known vulnerabilities in FTP service.",
    "ssh": "Potential weak passwords in SSH service.",
    "telnet": "Telnet is insecure and should not be used.",
    "http": "Check for outdated web servers or known exploits.",
    "https": "Check for SSL/TLS vulnerabilities.",
}

# Function to scan a single port and identify the service
def scan_port(ip, port, open_ports, vulnerabilities):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)  # Set timeout to 1 second
        if sock.connect_ex((ip, port)) == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            open_ports.append((port, service))
            print(f"Port {port} is open and running {service}.")
            if service in vulnerable_services:
                vulnerabilities.append((port, service, vulnerable_services[service]))

# Function to scan a range of ports concurrently
def scan_ports_concurrently(ip, start_port, end_port):
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

# Main function to get user input and start scanning
if __name__ == "__main__":
    ip = input("Enter IP address to scan: ")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print("Invalid IP address.")
        exit()

    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))

    print(f"Scanning {ip} from port {start_port} to {end_port}...")
    open_ports, vulnerabilities = scan_ports_concurrently(ip, start_port, end_port)

    if open_ports:
        print(f"Open ports: {[(port, service) for port, service in open_ports]}")
    else:
        print("No open ports found.")

    if vulnerabilities:
        print("Vulnerabilities found:")
        for port, service, vulnerability in vulnerabilities:
            print(f"Port {port} (service: {service}) - {vulnerability}")
    else:
        print("No known vulnerabilities found.")
