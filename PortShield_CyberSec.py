# Example IP Address: 127.0.0.1  
# Start Port: 2221
# End Port: 8080
# simulation of ports -> echo -e "220 (vsFTPd 3.0.3)" | ncat -l 2221  
# echo -e "SSH-2.0-OpenSSH_7.4" | ncat -l 2222
# echo -e "HTTP/1.1 200 OK\r\n\r\n" | ncat -l 8080
# nc 127.0.0.1 2221

# netstat -an | grep LISTEN  -> to learn open ports 
# sudo lsof -i -P -n | grep LISTEN --> PID associated with the port
# python PortShiled_CyberSec.py

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
    "hbci": "Specific vulnerabilities in HBCI service.",
    "commplex-main": "Vulnerabilities in Commplex Main service.",
    "afs3-fileserver": "Security issues in AFS3 File Server service.",
    "smtp": "Potential email relay and spamming vulnerabilities in SMTP service.",
    "pop3": "Risk of unauthorized access to email messages in POP3 service."

}


# grab the banner of the service running on a port -> for other cases that mentioned 
# such as port 80 not HTTP but working as SSH
def banner_grab(ip, port):
    with socket.socket() as s:
        s.settimeout(1)
        try:
            s.connect((ip, port))

            # HTTP  
            s.send(b'HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n' % ip.encode()) # goes to socket,
            banner = s.recv(1024).decode().strip() # response analyze,
            print(f"banner on port {port}: {banner}")
            if "HTTP" in banner: # if there is something related to http, it will counted as HTTP 
                return "http"

            # SSH 
            s.send(b'SSH-2.0-OpenSSH_7.4\r\n') # b -> bytes , 1024 bytes of data  2^10 -> memory alignment fit 
            banner = s.recv(1024).decode().strip()
            print(f"banner on port {port}: {banner}")
            if "SSH" in banner:
                return "ssh"

            # FTP 
            s.send(b'USER anonymous\r\n')
            banner = s.recv(1024).decode().strip()
            print(f"banner on port {port}: {banner}")
            if "220" in banner:
                return "ftp"

            # Telnet 
            s.send(b'\xFF\xFB\x01\xFF\xFB\x03\xFF\xFD\x1F')  # Telnet negotiation
            banner = s.recv(1024).decode().strip()
            print(f"banner on port {port}: {banner}")
            if "Telnet" in banner or "Welcome" in banner:
                return "telnet"

            # HTTPS 
            s.send(b'HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n' % ip.encode())
            banner = s.recv(1024).decode().strip()
            if "HTTPS" in banner:
                return "https"
            
            # hbci 
            if port == 3000: #change
                s.send(b'HBCI banner request\r\n')
                banner = s.recv(1024).decode().strip()
                print(f"banner on port {port}: {banner}")
                if "HBCI" in banner:
                    return "hbci"
                
            # commplex-main 
            if port == 5000: #change
                s.send(b'Commplex-Main banner request\r\n')
                banner = s.recv(1024).decode().strip()
                print(f"banner on port {port}: {banner}")
                if "Commplex-Main" in banner:
                    return "commplex-main"

            # afs3-fileserver 
            if port == 7000:  #change
                s.send(b'AFS3-FileServer banner request\r\n')
                banner = s.recv(1024).decode().strip()
                print(f"banner on port {port}: {banner}")
                if "AFS3-FileServer" in banner:
                    return "afs3-fileserver"
                
            # smtp
            if port == 0:  #change
                s.send(b'SMTP banner request\r\n')
                banner = s.recv(1024).decode().strip()
                print(f"banner on port {port}: {banner}")
                if "SMTP" in banner:
                    return "SMTP"

            # pop3
            if port == 0:  #change
                s.send(b'POP3 banner request\r\n')
                banner = s.recv(1024).decode().strip()
                print(f"banner on port {port}: {banner}")
                if "POP3" in banner:
                    return "POP3"
            
        except Exception as e:
            print(f"Error on port {port}: {e}")
            pass


    return "unknown"

# scan port
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

# scan a range of ports 
def scan_ports_range(ip, start_port, end_port):
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
    ip = input("Enter IP address to scan: ") # input IP address and port range
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print("Invalid IP address.")
        exit()

    start_port = int(input("Enter start port: ")) 
    end_port = int(input("Enter end port: "))

    print(f"Scanning {ip} from port {start_port} to {end_port}...")   # port scanning process
    open_ports, vulnerabilities = scan_ports_range(ip, start_port, end_port)


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
