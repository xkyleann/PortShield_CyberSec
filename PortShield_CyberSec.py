# Example IP Address: 127.0.0.1  
# Start Port: 2221
# End Port: 8080
# simulation of ports -> echo -e "HTTP/1.1 200 OK\r\n\r\n" | nc -l 8080
# echo -e "SSH-2.0-OpenSSH_7.4" | nc -l 2222
# echo -e "220 (vsFTPd 3.0.3)" | nc -l 21
# echo -e "Telnet Banner\r\n" | nc -l  23

#----
# Enter IP address to scan: 127.0.0.1
# Enter start port: 1
# Enter end port: 8080

"""
Scanning 127.0.0.1 from port 1 to 8080...
Port 21 is open and running ftp.
Port 23 is open and running telnet.
Port 2222 is open and running ssh.
Port 8080 is open and running http.
Open ports: [(21, 'ftp'), (23, 'telnet'), (2222, 'ssh'), (8080, 'http')]
Vulnerabilities found:
Port 21 (service: ftp) - Known vulnerabilities in FTP service.
Port 23 (service: telnet) - Telnet is insecure and should not be used.
Port 2222 (service: ssh) - Potential weak passwords in SSH service.
Port 8080 (service: http) - Check for outdated web servers or known exploits.
"""

import socket
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor

# descriptions
vulnerable_services = {
    "ftp": "Known vulnerabilities in FTP service.",
    "ssh": "Potential weak passwords in SSH service.",
    "telnet": "Telnet is insecure and should not be used.",
    "http": "Check for outdated web servers or known exploits.",
    "https": "Check for SSL/TLS vulnerabilities.",
    "hbci": "Specific vulnerabilities in HBCI service.",
    "commplex-main": "Vulnerabilities in Commplex Main service.",
    "afs3-fileserver": "Security issues in AFS3 File Server service.",
    "smtp": "Potential email relay and spamming vulnerabilities in SMTP service.",
    "pop3": "Risk of unauthorized access to email messages in POP3 service."
}

def banner_grab(ip, port):
    with socket.socket() as s:
        s.settimeout(1)
        try:
            s.connect((ip, port))
            # HTTP
            s.send(b'HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n' % ip.encode())
            banner = s.recv(1024).decode().strip()
            if "HTTP" in banner:
                return "http"
            # SSH
            s.send(b'SSH-2.0-OpenSSH_7.4\r\n')
            banner = s.recv(1024).decode().strip()
            if "SSH" in banner:
                return "ssh"
            # FTP
            s.send(b'USER anonymous\r\n')
            banner = s.recv(1024).decode().strip()
            if "220" in banner:
                return "ftp"
            # Telnet
            s.send(b'\xFF\xFB\x01\xFF\xFB\x03\xFF\xFD\x1F')  # Telnet negotiation
            banner = s.recv(1024).decode().strip()
            if "Telnet" in banner or "Welcome" in banner:
                return "telnet"
            # HTTPS
            s.send(b'HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n' % ip.encode())
            banner = s.recv(1024).decode().strip()
            if "HTTPS" in banner:
                return "https"
            # HBCI
            if port == 3000:
                s.send(b'HBCI banner request\r\n')
                banner = s.recv(1024).decode().strip()
                if "HBCI" in banner:
                    return "hbci"
            # Commplex-Main
            if port == 5000:
                s.send(b'Commplex-Main banner request\r\n')
                banner = s.recv(1024).decode().strip()
                if "Commplex-Main" in banner:
                    return "commplex-main"
            # AFS3-FileServer
            if port == 7000:
                s.send(b'AFS3-FileServer banner request\r\n')
                banner = s.recv(1024).decode().strip()
                if "AFS3-FileServer" in banner:
                    return "afs3-fileserver"
            # SMTP
            if port == 25 or port == 587:
                s.send(b'EHLO example.com\r\n')
                banner = s.recv(1024).decode().strip()
                if "SMTP" in banner:
                    return "smtp"
            # POP3
            if port == 110 or port == 995:
                s.send(b'USER test\r\n')
                banner = s.recv(1024).decode().strip()
                if "POP3" in banner:
                    return "pop3"

            # Other services based on port-specific banners...
            # You can add similar checks for other services
            
        except Exception as e:
            print(f"Error on port {port}: {e}")
            pass
    return "unknown"

def scan_port(ip, port, open_ports, vulnerabilities):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        if sock.connect_ex((ip, port)) == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            open_ports.append((port, service))
            print(f"Port {port} is open and running {service}.")
            if service in vulnerable_services:
                vulnerabilities.append((port, service, vulnerable_services[service]))

def scan_ports_range(ip, start_port, end_port):
    open_ports = []
    vulnerabilities = []
    with ThreadPoolExecutor(max_workers=100) as executor:  # Limit the number of concurrent threads
        futures = []
        for port in range(start_port, end_port + 1):
            futures.append(executor.submit(scan_port, ip, port, open_ports, vulnerabilities))
        for future in futures:
            future.result()  # Ensure all futures are completed

    return open_ports, vulnerabilities

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
    open_ports, vulnerabilities = scan_ports_range(ip, start_port, end_port)

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
