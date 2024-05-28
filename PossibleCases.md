## Case 1 

- netstat -an | grep LISTEN 
- TCP4 in port *.22
- TCP6 in port *.22
- TCP4 in port *.80
- TCP6 in port *.80

```bash
tcp4       0      0  *.22                   *.*                    LISTEN     
tcp6       0      0  *.22                   *.*                    LISTEN     
tcp4       0      0  *.80                   *.*                    LISTEN     
tcp6       0      0  *.80                   *.*                    LISTEN    
```

It means our both **22 and 80 ports** are **open**. 

- To check which vulnerabilities occur, we have to type this command.

 ```bash
sudo lsof -i -P -n | grep LISTEN
```

It will give output like this: 

```bash
sshd       5335            root    4u  IPv6 0x39d7de6dc7705f2f      0t0    TCP *:80 (LISTEN)
sshd       5335            root    5u  IPv4 0x39d7de728425321f      0t0    TCP *:80 (LISTEN)
sshd       5335            root    6u  IPv6 0x39d7de6dc7708f2f      0t0    TCP *:22 (LISTEN)
sshd       5335            root    7u  IPv4 0x39d7de728425268f      0t0    TCP *:22 (LISTEN)


- So we can see that **"ssh"**: "Potential weak passwords in SSH service can be occur.
- Let's run the program.

```bash
python PortShield_CyberSec.py
```

- After we run we have to Enter IP address.
- If IP address unknown this command can be entered:

```bash
ipconfig
```

```bash
Enter IP address to scan: XXX.XXX.X.XX
Enter start port: 1
Enter end port: 80
Scanning XXX.XXX.X.XX from port 1 to 80...
banner on port 22: SSH-2.0-OpenSSH_9.6
banner on port 22: Invalid SSH identification string.
Port 22 is open and running ssh.
banner on port 80: SSH-2.0-OpenSSH_9.6
banner on port 80: Invalid SSH identification string.
Port 80 is open and running ssh.
Open ports: [(22, 'ssh'), (80, 'ssh')]
Vulnerabilities found:
Port 22 (service: ssh) - Potential weak passwords in SSH service.
Port 80 (service: ssh) - Potential weak passwords in SSH service.
```

- As a result, program scanned all the ports successfully with right vulnerabilities.

--- 

## Case 2
- Testing program with **virtual ports** as simulation.

- To create virtual ports:

```bash
echo -e "220 (vsFTPd 3.0.3)" | ncat -l 2221  
```

```bash
echo -e "SSH-2.0-OpenSSH_7.4" | ncat -l 2222
```

```bash
echo -e "HTTP/1.1 200 OK\r\n\r\n" | ncat -l 8080
```

- There has to be 3 different terminals opened, and one more for the running the program.
- Port 2221 has to be generated with **ftp vulnerabilities**
- Port 2222 has to be generated with **ssh vulnerabilities**
- Port 8080 has to be generated with **http vulnerabilities**

- If port is occupied, please replace port numbers with another one.

 <img width="1141" alt="Ekran Resmi 2024-05-28 14 59 12" src="https://github.com/xkyleann/PortShield_CyberSec/assets/128597547/76a01654-e582-414f-a1fa-6ec65689663e">

- As seen, ports are opened: 
```bash
tcp4       0      0  *.8080                 *.*                    LISTEN     
tcp6       0      0  *.8080                 *.*                    LISTEN     
tcp4       0      0  *.2222                 *.*                    LISTEN     
tcp6       0      0  *.2222                 *.*                    LISTEN     
tcp4       0      0  *.2221                 *.*                    LISTEN
tcp6       0      0  *.2221  
```

```bash
http       5335            root    4u  IPv6 0x39d7de6dc7705f2f      0t0    TCP *:8080 (LISTEN)
http       5335            root    5u  IPv4 0x39d7de728425321f      0t0    TCP *:8080 (LISTEN)
sshd       5335            root    6u  IPv6 0x39d7de6dc7708f2f      0t0    TCP *:2222 (LISTEN)
sshd       5335            root    7u  IPv4 0x39d7de728425268f      0t0    TCP *:2222 (LISTEN)
ftp        5335            root    6u  IPv6 0x39d7de6dc7708f2f      0t0    TCP *:2221 (LISTEN)
ftp        5335            root    7u  IPv4 0x39d7de728425268f      0t0    TCP *:2221 (LISTEN)
```

- As seen, ports are opened: 

```bash
Enter IP address to scan: XXX.XXX.X.XX
Enter start port: 2020
Enter end port: 8080
Scanning XXX.XXX.X.XX from port 1 to 80...
banner on port 8080: HTTP/1.1 200 OK\r\n\r\n
banner on port 8080: Invalid HTTP identification string.
Port 8080 is open and running http.
banner on port 2222: SSH-2.0-OpenSSH_7.4
banner on port 2222: Invalid SSH identification string.
Port 2222 is open and running ssh.
banner on port 2221: 220 (vsFTPd 3.0.3)
banner on port 2221: Invalid FTP identification string.
Port 2221 is open and running ftp.
banner on port 80: SSH-2.0-OpenSSH_9.6
Open ports: [(8080, 'http'), (2222, 'ssh'),(2221,'ftp')]
Vulnerabilities found:
Port 8080 (service: http) - Check for outdated web servers or known exploits.
Port 2222 (service: ssh)  - Potential weak passwords in SSH service.
Port 2221 (service: ftp)  - Known vulnerabilities in FTP service.
```
---

<img width="810" alt="Ekran Resmi 2024-05-28 17 22 46" src="https://github.com/xkyleann/PortShield_CyberSec/assets/128597547/917b5203-4c7b-4f81-bd83-3c53d86023c7">



