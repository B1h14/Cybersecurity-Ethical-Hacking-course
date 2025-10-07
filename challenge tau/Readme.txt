In this code i worked on the first part of the challenge : denial of service

I tested it with the virtual machine of the first challenge : mu 

The code first looks for packets going throught the device "any"

When a TCP connection attempt packet passes through the device an rst packet will be sent immediatly to close the connection

Usage:
1. Compile the code with make
2. Run the program with sudo ./hack
3. input the target port

