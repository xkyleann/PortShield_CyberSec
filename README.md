#  Port Scanner - Cybersecurity Project

This is a cybersecurity project that includes a basic port scanner with the added feature of identifying services running on open ports and checking for known vulnerabilities.

## Table of Contents

| No # | Table of Contents                                                                   |
| --- | ----------------------------------------------------------------------- |
| **1**   | [**Project Description**](https://github.com/xkyleann/PortShield_CyberSec/blob/main/README.md) |
| **2**   | [**User Stories and Acceptance Criteria**](https://github.com/xkyleann/PortShield_CyberSec/blob/main/PortShield_Documentation.xlsx) |
| **3**   | [**Project Base**](https://github.com/xkyleann/PortShield_CyberSec/blob/main/PortShield_CyberSec.py) |
| **4**   | [**Possible Cases**](https://github.com/xkyleann/PortShield_CyberSec/blob/main/PossibleCases.md) |



## Introduction

Cybersecurity Project, Port Scanner is a tool designed to scan a range of ports on a given IP address, identify the services running on open ports, and check for known vulnerabilities associated with these services. This tool is useful for security assessments, network diagnostics, and vulnerability management.

## Features

- Scan a range of ports on a given IP address.
- Identify services running on open ports.
- Check for known **vulnerabilities** associated with identified services.
- **Multithreaded scanning** for faster performance.

## Setup

### Prerequisites

- Python 3.x installed on your system. You can download it from [python.org](https://www.python.org/).

### Installation
**1.** Clone the repository:

```bash
git clone https://github.com/yourusername/PortShield-CyberSec.git
```

**2.** Change to the project directory:
```bash
cd PortShield-CyberSec
```

**3.** **(Optional)** Create a virtual environment and activate it:

```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

**4.** Install necessary dependencies (if any):

```bash
pip install -r requirements.txt  # Currently, no external dependencies are required
```

## Usage
**1.** Run the port scanner script:
```bash
python PortShield_CyberSec.py
```

**2.** Enter the IP address you want to scan when prompted:
```bash
Enter IP address to scan: 192.168.1.1
```

**3.** Enter the start port and end port for the range you want to scan:
```bash
Enter start port: 20
Enter end port: 80
```

**4.** View the results of the scan, including open ports, identified services, and any known vulnerabilities. **Example output:**
```bash
Scanning 192.168.1.1 from port 20 to 80...
Port 22 is open and running ssh.
Port 80 is open and running http.
Open ports: [(22, 'ssh'), (80, 'http')]
Vulnerabilities found:
Port 22 (service: ssh) - Potential weak passwords in SSH service.
Port 80 (service: http) - Check for outdated web servers or known exploits.
```

## To test ports (Cases)

**1** FTP on Port 2221
```bash
echo -e "220 (vsFTPd 3.0.3)" | nc -l 2221
```

**2** SSH on Port 2222
```bash
echo -e "SSH-2.0-OpenSSH_7.4" | ncat -l 2222
```

**3** HTTP on Port 8080
```bash
echo -e "HTTP/1.1 200 OK\r\n\r\n" | ncat -l 8080 
```

**Expected Output** 
- IP Address: 127.0.0.1
- Start Port: 2221
- End Port: 8080

```bash

Enter IP address to scan: 127.0.0.1
Enter start port: 2221
Enter end port: 8080
Scanning 127.0.0.1 from port 2221 to 8080...
DEBUG: Banner from port 2221 - 220 (vsFTPd 3.0.3)
Port 2221 is open and running ftp.
DEBUG: Banner from port 2222 - SSH-2.0-OpenSSH_7.4
Port 2222 is open and running ssh.
DEBUG: Banner from port 8080 - HTTP/1.1 200 OK
Port 8080 is open and running http.
Open ports: [(2221, 'ftp'), (2222, 'ssh'), (8080, 'http')]
Vulnerabilities found:
Port 2221 (service: ftp) - Known vulnerabilities in FTP service.
Port 2222 (service: ssh) - Potential weak passwords in SSH service.
Port 8080 (service: http) - Check for outdated web servers or known exploits.
```


