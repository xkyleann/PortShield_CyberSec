#  Port Scanner - Cybersecurity Project

This is a cybersecurity project that includes a basic port scanner with the added feature of identifying services running on open ports and checking for known vulnerabilities.

## Table of Contents

| No # | Table of Contents                                                                   |
| --- | ----------------------------------------------------------------------- |
| **1**   | [**Project Description**](https://github.com/xkyleann/FIRFilters_Labs/blob/main/1Simulink_MATLAB.slx) |
| **2**   | [**User Stories**](https://github.com/xkyleann/FIRFilters_Labs/blob/main/1Simulink_MATLAB.slx) |
| **3**   | [**Instruction**](https://github.com/xkyleann/FIRFilters_Labs/blob/main/1Simulink_MATLAB.slx) |
| **4**   | [**Project Base**](https://github.com/xkyleann/FIRFilters_Labs/blob/main/1Simulink_MATLAB.slx) |
| **5**   | [**Acceptance Criteria**](https://github.com/xkyleann/FIRFilters_Labs/blob/main/1Simulink_MATLAB.slx) |


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

