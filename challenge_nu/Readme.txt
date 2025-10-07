# μ-Challenge: Buffer Overflow Exploit

This project contains an exploit for a vulnerable echo server running in a VirtualBox VM. The server is vulnerable to a buffer overflow, which can be used to gain remote shell access and modify the hosted webpage to add your name.
The file client.c when executed reads commands from the terminal and executes them.
---

## 📦 Files

- `client.c`: Exploit code that connects to the server, sends a crafted payload, and gives shell access.
- `README.txt`: This file.

---

## 🎯 Objective

Exploit a buffer overflow vulnerability in a server running at:

- **IP**: `192.168.56.103`
- **Port**: `4321`

The goal is to execute arbitrary shell commands on the VM and modify `/var/www/html/index.html` to add your name.

---

## ⚙️ Setup Instructions

### 1. Install VirtualBox

If not installed already, download and install VirtualBox:

📎 https://www.virtualbox.org/

### 2. Import Virtual Machine

- Open VirtualBox
- Select **File → Import Appliance**
- Import the VM provided with the μ-challenge

### 3. Configure Host-Only Network

- Create a Host-Only Network: `vboxnet0`
- Set IP: `192.168.56.1/24`
- Disable the DHCP server
- Verify with `ifconfig` or `ip addr` that `vboxnet0` exists

---

## 🔍 Vulnerability Summary

The vulnerable server contains the following unsafe code:

```c
char greeting_text[128];
char buf[256] = {0};
fgets(buf, sizeof(buf), stdin);
strcpy(greeting_text, "Hello, dear ");
strcat(greeting_text, buf);
