# Example IP Address: 127.0.0.1
# Start Port: 2221
# End Port: 8080
# echo -e "220 (vsFTPd 3.0.3)" | ncat -l 2221
# echo -e "SSH-2.0-OpenSSH_7.4" | ncat -l 2222
# echo -e "HTTP/1.1 200 OK\r\n\r\n" | ncat -l 8080
import socket
import threading
import ipaddress

# descriptions
vulnerable_services = {
    "ftp": "Known vulnerabilities in FTP service.",
    "ssh": "Potential weak passwords in SSH service.",
    "telnet": "Telnet is insecure and should not be used.",
    "http": "Check for outdated web servers or known exploits.",
    "https": "Check for SSL/TLS vulnerabilities.",
}

# grab the banner of the service running on a port -> for other cases that mentioned 
# such as port 80 not HTTP but working as SSH
def banner_grab(ip, port):
    with socket.socket() as s:
        s.settimeout(1)
        try:
            s.connect((ip, port))

            # HTTP Check
            s.send(b'HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n' % ip.encode())
            banner = s.recv(1024).decode().strip()
            if "HTTP" in banner:
                return "http"

            # SSH Check
            s.send(b'SSH-2.0-OpenSSH_7.4\r\n')
            banner = s.recv(1024).decode().strip()
            if "SSH" in banner:
                return "ssh"

            # FTP Check
            s.send(b'USER anonymous\r\n')
            banner = s.recv(1024).decode().strip()
            if "220" in banner:
                return "ftp"

            # Telnet Check
            s.send(b'\xFF\xFB\x01\xFF\xFB\x03\xFF\xFD\x1F')  # Telnet negotiation
            banner = s.recv(1024).decode().strip()
            if "Telnet" in banner or "Welcome" in banner:
                return "telnet"

            # HTTPS Check
            s.send(b'HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n' % ip.encode())
            banner = s.recv(1024).decode().strip()
            if "HTTPS" in banner:
                return "https"
        except Exception as e:
            pass

    return "unknown"

# scan port
def scan_port(ip, port, open_ports, vulnerabilities):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        if sock.connect_ex((ip, port)) == 0:
            service = banner_grab(ip, port)
            open_ports.append((port, service))
            print(f"Port {port} is open and running {service}.")
            if service in vulnerable_services:
                vulnerabilities.append((port, service, vulnerable_services[service]))

# scan a range of ports concurrently
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

if __name__ == "__main__":
    # input IP address and port range
    ip = input("Enter IP address to scan: ")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print("Invalid IP address.")
        exit()

    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))

    # port scanning process
    print(f"Scanning {ip} from port {start_port} to {end_port}...")
    open_ports, vulnerabilities = scan_ports_concurrently(ip, start_port, end_port)

    # display results 
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
