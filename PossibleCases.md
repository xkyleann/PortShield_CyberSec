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
- sudo lsof -i -P -n | grep LISTEN

It will give output like this: 

```bash
sshd      5335            root    4u  IPv6 0x39d7de6dc7705f2f      0t0    TCP *:80 (LISTEN)
sshd       5335            root    5u  IPv4 0x39d7de728425321f      0t0    TCP *:80 (LISTEN)
sshd       5335            root    6u  IPv6 0x39d7de6dc7708f2f      0t0    TCP *:22 (LISTEN)
sshd       5335            root    7u  IPv4 0x39d7de728425268f      0t0    TCP *:22 (LISTEN)
```

- So we can see that **"ssh"**: "Potential weak passwords in SSH service can be occur.
- Let's run the program.

```bash
python PortShield_CyberSec.py
```

- After we run we have to Enter IP address.
- If IP address unknown this command can be entered:

```bash
ipconfig getifaddr en0
```

```bash
Enter IP address to scan: XXX.XXX.X.XX
Enter start port: 1
Enter end port: 80
Scanning 192.168.1.26 from port 1 to 80...
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
- Testing program with virtual ports as simulation.

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
