# Cybersecurity Ethical hacking course

A collection of security challenges demonstrating various network vulnerabilities including buffer overflow exploitation, TCP SYN flood attacks, and TCP connection hijacking.

> ⚠️ **Educational Purpose Only**: This repository is for educational and authorized security testing purposes only. 
## 📋 Table of Contents

- [Overview](#overview)
- [Projects](#projects)
  - [1. Buffer Overflow Exploit](#1-buffer-overflow-exploit)
  - [2. Remote Command Execution via Buffer Overflow](#2-remote-command-execution-via-buffer-overflow)
  - [3. TCP SYN Flood Attack](#3-tcp-syn-flood-attack)
  - [4. TCP Connection Hijacking](#4-tcp-connection-hijacking)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Disclaimer](#disclaimer)

## 🎯 Overview

This repository contains four security research projects demonstrating common network vulnerabilities and exploitation techniques:

1. **Buffer Overflow with Shell Access** - Exploits a vulnerable echo server to gain remote shell
2. **Remote Command Injection** - Uses buffer overflow to execute arbitrary commands and install SSH backdoor
3. **SYN Flood DoS Attack** - Performs TCP SYN flood using raw sockets with IP spoofing
4. **TCP RST Injection** - Hijacks TCP connections by injecting RST packets

Each project includes source code, compilation instructions, and detailed documentation.

## 📁 Projects

### 1. Buffer Overflow Exploit

**Directory**: Challenge nu

Exploits a stack-based buffer overflow in an echo server to execute shellcode and gain remote shell access.

**Files**:
- `client.c` - Exploit client that sends crafted payload
- `Makefile` - Build configuration

**Features**:
- Executes `/bin/sh` shellcode via buffer overflow
- Demonstrates return address overwriting

**Usage**:
```bash
make
./client
# Enter commands to execute on target system
```

**Target Configuration**:
- IP: `192.168.56.103`
- Port: `4321`

---

### 2. Remote Command Execution via Buffer Overflow

**Directory**: Challenge mu

Exploits buffer overflow vulnerability to execute system commands and establish persistent SSH access.

**Files**:
- `client.c` - Main exploit client with SSH configuration
- `client_2.c` - Alternative client implementation
- `Makefile` - Build configuration

**Features**:
- Buffer overflow exploitation (117-byte padding)
- Automatic SSH server installation and configuration
- Public key authentication setup
- Remote command execution

**Configuration**:
```
#define IP "192.168.56.101"
#define PORT 1234
#define SSH "PUBLIC SSH KEY"  // Insert your SSH public key here
```

**Functions**:
- `execute_command()` - Sends commands via exploited buffer
- `configure_ssh()` - Sets up SSH server with custom config
- `insert_ssh()` - Installs your SSH public key

**Usage**:
```bash
# 1. Edit client.c and add your SSH public key at line 13
# 2. Compile and run
make
./client

# 3. Connect via SSH after successful exploitation
ssh root@192.168.56.101
```

---

### 3. TCP SYN Flood Attack

**Directory**: Challenge sigma (SYN Flood)

Implements a TCP SYN flood denial-of-service attack using raw sockets with randomized source IP addresses.

**Files**:
- `rawip.c` - SYN flood implementation
- `header.h`, `header.c` - Custom network header definitions
- `Makefile` - Build configuration

**Features**:
- Raw socket creation with `IPPROTO_RAW`
- Custom IP and TCP header crafting
- Randomized source IP spoofing
- Configurable packet timing
- Proper TCP/IP checksum calculation

**Technical Details**:
- Uses pseudo-header for TCP checksum
- Sends SYN packets with random source ports
- Maximum effective delay: 50ms between packets

**Usage**:
```bash
make
sudo ./rawip [timeout_ms]
# Example: sudo ./rawip 50
```

**Parameters**:
- `timeout_ms` - Delay between packets (default: 1000ms, recommended: ≤50ms)

**Target Configuration**:
```c
#define TARGET_IP "192.168.56.101"
#define TARGET_PORT 2000
```

---

### 4. TCP Connection Hijacking

**Directory**: Challenge tau (DoS/Connection Reset)

Monitors network traffic and terminates TCP connections by injecting RST packets.

**Files**:
- `rawip.c` - Connection hijacking implementation using libpcap
- `header.h`, `header.c` - Network protocol structures
- `Makefile` - Build configuration with libpcap

**Features**:
- Packet capture using libpcap
- TCP connection monitoring
- RST packet injection
- Real-time connection termination
- Support for multiple link types (Ethernet, Linux SLL)

**Technical Implementation**:
- Captures packets on any interface
- Filters by target port
- Calculates proper sequence numbers
- Injects spoofed RST packets

**Usage**:
```bash
make
sudo ./rawip
# Enter target port when prompted
```

**Requirements**:
- libpcap-dev installed
- Root/sudo privileges for packet capture
- Raw socket access

---

## 🔧 Prerequisites

### System Requirements
- Linux operating system (tested on WSL)
- GCC compiler
- Make build system
- Root/sudo privileges (for raw socket operations)

### Software Dependencies

```bash
# Essential build tools
sudo apt-get update
sudo apt-get install build-essential gcc make

# For TCP hijacking project
sudo apt-get install libpcap-dev

# For VirtualBox testing environment
sudo apt-get install virtualbox
```

### Network Setup

For testing with VirtualBox VMs:

1. Create Host-Only Network:
   - Open VirtualBox → File → Host Network Manager
   - Create network: `vboxnet0`
   - Configure IPv4: `192.168.56.1/24`
   - Disable DHCP

2. Verify network:
```bash
ip addr show vboxnet0
# or
ifconfig vboxnet0
```

## 🚀 Setup

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/network-security-exploits.git
cd network-security-exploits
```

### 2. Build Projects

Each project has its own Makefile:

```bash
# Buffer Overflow Exploit
cd challenge1
make

# Remote Command Execution
cd challenge2
make

# SYN Flood Attack
cd challenge3
make

# TCP Hijacking
cd challenge4
make
```

### 3. Configuration

Update target IP addresses and ports in source files as needed:

```c
// Example: Modify these constants in each project
#define TARGET_IP "192.168.56.101"
#define TARGET_PORT 1234
```

### 4. Run Exploits

```bash
# Most exploits require root privileges
sudo ./client
sudo ./rawip
```

## 📚 Educational Notes

### Buffer Overflow Basics
- Stack layout and memory organization
- Return address overwriting
- NOP sled technique
- Shellcode execution

### Network Attack Techniques
- Raw socket programming
- IP spoofing
- TCP handshake manipulation
- Packet injection

### Defense Mechanisms
- ASLR (Address Space Layout Randomization)
- Stack canaries
- DEP/NX (Data Execution Prevention)
- SYN cookies
- Connection rate limiting

## 🛡️ Disclaimer

**IMPORTANT**: This code is provided for educational purposes only.

- ✅ Use only on systems you own or have explicit written permission to test
- ✅ Intended for security research and authorized penetration testing
- ✅ Help improve security by understanding vulnerabilities
- ❌ Unauthorized access to computer systems is illegal
- ❌ The authors are not responsible for misuse of this code
- ❌ Using these techniques without permission may result in criminal charges

**Legal Warning**: Unauthorized computer access, denial-of-service attacks, and system compromise are serious crimes in most jurisdictions. Always obtain proper authorization before testing security measures.

## 📖 References

- [Buffer Overflow Tutorial](https://www.thegeekstuff.com/2013/06/buffer-overflow/)
- [TCP/IP Protocol Suite](https://en.wikipedia.org/wiki/Internet_protocol_suite)
- [Raw Sockets Programming Guide](http://www.tcpipguide.com/)
- [libpcap Documentation](https://www.tcpdump.org/manpages/pcap.3pcap.html)

## 📝 License

This project is provided as-is for educational purposes. Users are responsible for ensuring their use complies with applicable laws and regulations.


**Remember**: With great power comes great responsibility. Use these tools ethically and legally.
