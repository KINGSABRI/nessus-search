# nessus-search
parse nessus report and search for specific data. The script has been built to help after running nessus multiple scans during pentest and at writing the report.

## Requirements
```
gem install ruby-nessus
```

## Usage

```
ruby nessus-search.rb -h
Usage: nessus-search [options]
    -p, --path PATH                  File or directory path
    -l, --list RISK                  List all findings
                                       risk levels: critical, high, medium, low, informational, all
    -v, --vuln VUL_NAME              Find vulnerabilities that match name
    -V, --vuln-hosts VUL_NAME        Find vulnerable hosts by specific vulnerability name
        --output                     Show the vulnerability output for the vulnerable hosts (verbose outputs) use it with '-V/--vuln-hosts'
    -i, --ip IP_ADDR                 Find vulnerabilities for a specific IP address
    -S, --services                   List discovered services and servers with its ports
    -s, --srv SRV_NAME               Find hosts by service name (use "" to list all services for all hosts)
    -c, --cve CVE                    Find vulnerability and hosts by CVE
    -I, --info VUL_NAME              Get the vulnerability information (Only exact name maches)
    -h, --help                       Prints this help
```

- List critical, high, medium, low, informational or all vulnerabilties
```
$ ruby nessus-search.rb -p nessus-scans/ -l all
$ ruby nessus-search.rb -p nessus-scans -l critical
$ ruby nessus-search.rb -p nessus-scans -l high
$ ruby nessus-search.rb -p nessus-scans -l medium
```
- Find full vulnerability name or all vulnerabilties that match a string
```
$ ruby nessus-search.rb -p nessus-scans -v Apache 2.4.x

[+] Matching vulnerabilties for 'Apache':
None      Apache HTTP Server Version
None      Apache Tomcat Detection
Medium    Apache Server ETag Header Information Disclosure
Medium    Apache Tomcat Default Files
None      Apache Banner Linux Distribution Disclosure
Medium    Apache 2.4.x < 2.4.41 Multiple Vulnerabilities
High      Apache ActiveMQ Web Console Default Credentials
None      Apache ActiveMQ Detection
```

- Find all hosts that are vulnerable with a specific vulnerability (the --output shows the plugin PoC output)
```
$ ruby nessus-search.rb -p nessus-scans -V "Apache Server ETag Header Information Disclosure" --output

[+] Vulnerable hosts: (2)
192.168.100.60 www (443/tcp)
192.168.100.61 www (443/tcp)
```

- Find all vulnerabilties for a specific host
```
$ ruby nessus-search.rb -p nessus-scans -i "192.168.100.61"

[*] List of vulnerabilties for '192.168.100.61' host

[+] Critical: (1)
OpenSSL Unsupported
----------

[+] High: (8)
Unsupported Web Server Detection
OpenSSL < 0.9.8w ASN.1 asn1_d2i_read_bio Memory Corruption
...DETUCTED...
SSL Version 2 and 3 Protocol Detection
iSCSI Unauthenticated Target Detection
----------
AFP Server Directory Traversal
OpenSSL < 0.9.8l Multiple Vulnerabilities
OpenSSL 0.9.8 < 0.9.8zc Multiple Vulnerabilities (POODLE)
...DETUCTED...
SMB Signing not required
Samba Badlock Vulnerability

[+] Medium: (24)
AFP Server Directory Traversal
OpenSSL < 0.9.8l Multiple Vulnerabilities
OpenSSL 0.9.8 < 0.9.8zc Multiple Vulnerabilities (POODLE)
...DETUCTED...
SMB Signing not required
Samba Badlock Vulnerability
----------

[+] Low: (1)
SSL RC4 Cipher Suites Supported (Bar Mitzvah)
----------

[+] Informational: (42)
Common Platform Enumeration (CPE)
Nessus Scan Information
...DETUCTED...
Windows NetBIOS / SMB Remote Host Information Disclosure
Microsoft Windows SMB Service Detection
----------
```

- Get detailed information about vulnerability 
```
$ ruby nessus-search.rb -p nessus-scans -I "Apache Server ETag Header Information Disclosure"

[+] Vulnerability information
- Name: 
Apache Server ETag Header Information Disclosure

- severity:
2

- risk: 
Medium

- description:
The remote web server is affected by an information disclosure vulnerability due to the ETag header providing sensitive information that could aid an attacker, such as the inode number of requested files.

- solution:
Modify the HTTP ETag header of the web server to not include file inodes in the ETag header calculation. Refer to the linked Apache documentation for more information.

- cve:
CVE-2003-1418

- Output:
Nesus was able to determine that the Apache Server listening on
port 43 leaks the servers inode numbers in the ETag HTP
Header field : 
 Source : ETag: "111111-2222-00000000000"
 Inode number : 555555
 File size : 391 bytes
 File modification time : Jul. 1, 2019 at 09:19:17 GMT
```

- List all discovered services and servers from informational plugins (Service Detection|Server Detection)
```
$ ruby nessus-search.rb -p nessus-scans --services

[+] List of services: (525)
www (443/tcp)
www (80/tcp)
ssh (22/tcp)
ntp (123/udp)
slp (427/tcp)
telnet (23/tcp)
cim_listener (5989/tcp)
cim_listener (5988/tcp)
www (3900/tcp)
ssh (115/tcp)
...DETUCTED...
```


