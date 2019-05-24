#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <unistd.h>


typedef struct ip_hdr { //定义IP首部 
    uint8_t ver_and_len; //4位IP版本号+4位首部长度
    uint8_t tos; //8位服务类型TOS 
    uint16_t total_len; //16位总长度（字节） 
    uint16_t id; //16位标识 
    uint16_t slice; //3位标志位+13位片位移 
    uint8_t ttl; //8位生存时间 TTL 
    uint8_t protocol; //8位协议 (TCP, UDP 或其他) 
    uint16_t checksum; //16位IP首部校验和 
    uint32_t source_ip; //32位源IP地址 
    uint32_t dest_ip; //32位目的IP地址 
}IP_HEADER, *PIP_HEADER; 


typedef struct tcp_hdr //定义TCP首部 
{ 
    uint16_t source_port; //16位源端口 
    uint16_t dest_port; //16位目的端口 
    uint32_t seq; //32位序列号 
    uint32_t ack; //32位确认号 
    uint8_t len_and_res;//4位首部长度/4位保留字 
    uint8_t res_and_flag; //2位保留字和6位标志位
    uint16_t win; //16位窗口大小
    uint16_t checksum; //16位校验和
    uint16_t urp; //16位紧急数据偏移量
}TCP_HEADER, *PTCP_HEADER; 

typedef struct pseudo_header
{
    uint32_t source_addr;
    uint32_t dest_addr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
}PSEUDO_HEADER, *PPSEUDO_HEADER;




enum CLIENT_STATE{
    CLOSED, SYN_SENT, ESTABLISHED
};


uint32_t sequence = 0;
#define DEST_PORT 80
#define SOURCE_PORT 1234
#define BUFFER_SIZE 1024
#define DEST_IP "14.215.177.38"
#define INTERFACE "enp1s0"  // local interface


uint16_t check_sum(uint16_t *ptr, int nbytes);


int main(int argc, char *argv[]){
    int sockfd, i;
    char send_packet[BUFFER_SIZE];
    char recv_packet[BUFFER_SIZE];
    enum CLIENT_STATE state = CLOSED;


    // init buff, ip and tcp
    memset(send_packet, 0, BUFFER_SIZE);
    memset(recv_packet, 0, BUFFER_SIZE);
    PIP_HEADER ip = (PIP_HEADER)send_packet;
    PTCP_HEADER tcp = (PTCP_HEADER)(send_packet + sizeof(IP_HEADER));
    PSEUDO_HEADER pse; // pseudo header is used to calculate the checksum of TCP header

/*    
    // init server
    struct hostent* he = gethostbyname(argv[1]); // e.g., www.baidu.com
    if(he == NULL){
        perror("Failed to invoke gethostbyname\n");
        return 1;
    }
    char** addr_list = he->h_addr_list;
    for(i = 0; addr_list[i] != NULL; i++)
        printf("%s\n", addr_list[i]);

    for(i = 0; addr_list[i] != NULL; i++) {
        printf("%s ", inet_ntoa(*addr_list[i]));
    }
*/


    struct sockaddr_in sin;
    sin.sin_family = PF_INET;
    sin.sin_port = htons(DEST_PORT);
    //sin.sin_addr.s_addr = addr_list[i]->s_addr;
    sin.sin_addr.s_addr = inet_addr(DEST_IP);


    // get the host ip of interface
    struct in_addr source_ip;
    struct ifaddrs *ifa = NULL;
    getifaddrs(&ifa);
    for( ; ifa != NULL; ifa = ifa->ifa_next){
        if(ifa->ifa_addr->sa_family == AF_INET && !strcmp(INTERFACE, ifa->ifa_name)){
            // check it is IPv4 && the right interface
            source_ip = ((struct sockaddr_in*)(ifa->ifa_addr))->sin_addr;
            break;
        }
    }

    if(ifa == NULL){
        perror("Failed to find the local addr\n");
        exit(0);
    }

    // ip header
    ip->ver_and_len = 0x45;
    ip->tos = 0x00;
    ip->total_len = sizeof(IP_HEADER) + sizeof(TCP_HEADER);
    ip->id = 0x0000;
    ip->slice = 0x0040;
    ip->ttl = 0x40;
    ip->protocol = IPPROTO_TCP;
    ip->checksum = 0;
    ip->source_ip = source_ip.s_addr;
    ip->dest_ip = sin.sin_addr.s_addr;
    ip->checksum = check_sum((uint16_t*)ip, ip->total_len);


    // tcp header
    tcp->source_port = htons(SOURCE_PORT);
    tcp->dest_port = htons(DEST_PORT);
    tcp->seq = htonl(sequence);
    tcp->ack = 0x0;
    tcp->len_and_res = 0x50;
    tcp->res_and_flag = 0x02;
    tcp->win = 0x0fff;
    tcp->checksum = 0x0;
    tcp->urp = 0x0;

    // pseudo tcp header
    pse.source_addr = ip->source_ip;
    pse.dest_addr = ip->dest_ip;
    pse.placeholder = 0;
    pse.protocol = IPPROTO_TCP;
    pse.tcp_length = htons(sizeof(TCP_HEADER));

    // tcp checksum
    int pse_and_tcp = sizeof(PSEUDO_HEADER) + sizeof(TCP_HEADER);
    void* pse_header = malloc(pse_and_tcp);
    memcpy(pse_header, (void*)&pse, sizeof(PSEUDO_HEADER));
    memcpy((uint8_t*)pse_header + sizeof(PSEUDO_HEADER), tcp, sizeof(TCP_HEADER));
    tcp->checksum = check_sum((uint16_t*)pse_header, pse_and_tcp);


    // create socket fd used to emulate 3-way handshake
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP))== -1){    
        perror("Failed to create raw_socket\n");
        exit(0);
    }

    int one = 1;
    // IP_HDRINCL informs kernel not to create an ip header
    if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){
        perror("Failed to invoke setsockopt\n");
        close(sockfd);
        exit(0);
    }

    
    // first handshake: SYN
    if(sendto(sockfd, send_packet, ip->total_len, 0, (struct sockaddr*)&sin, sizeof(sin)) < 0){
        perror("Failed to send SYN");
        close(sockfd);
        exit(0);
    }
    printf("Three-way handshake: send SYN!\n");
    sequence++;
    state = SYN_SENT;

    while(1){
        int n = recv(sockfd, recv_packet, sizeof(recv_packet), 0);
        if (n == -1){
            perror("recv error!\n");
            close(sockfd);
            exit(0);
        } else if (n == 0)
            continue;

        PIP_HEADER recv_ip = (PIP_HEADER)recv_packet;
        if(recv_ip->protocol == IPPROTO_TCP && recv_ip->source_ip == sin.sin_addr.s_addr){
            // right ip
            PTCP_HEADER recv_tcp = (PTCP_HEADER)(((uint8_t*)recv_packet) + sizeof(IP_HEADER));
            if(recv_tcp->dest_port == htons(SOURCE_PORT) && recv_tcp->source_port == htons(DEST_PORT) && recv_tcp->ack == htonl(sequence)){
                // second handshake ACK+SYN
                printf("Three-way handshake: receive SYN + ACK!\n");
                tcp->ack = htonl(ntohl(recv_tcp->seq) + 1);
                tcp->res_and_flag = 0x10;
                tcp->seq = htonl(sequence);
                memcpy((uint8_t*)pse_header + sizeof(PSEUDO_HEADER), tcp, sizeof(TCP_HEADER));
                tcp->checksum = check_sum((uint16_t*)pse_header, pse_and_tcp);

                memset(recv_packet, 0, n);
                if(sendto(sockfd, send_packet, ip->total_len, 0, (struct sockaddr*)&sin, sizeof(sin)) < 0){
                    perror("Failed to send ACK");
                    close(sockfd);
                    exit(0);
                }
                    
                
                printf("Three-way handshake: send ACK!\n");
                state = ESTABLISHED;
                break;
            }
        }
    }

    return 0;
}


uint16_t check_sum(uint16_t *ptr, int nbytes){
    register uint64_t sum = 0;
    uint16_t oddbyte;

    while (nbytes > 1){
        sum += *ptr++;
        nbytes -= 2;
    }

    if(nbytes == 1){
        oddbyte = 0;
        *((uint8_t*)&oddbyte) = *(uint8_t*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);

    return (uint16_t)~sum;
}

