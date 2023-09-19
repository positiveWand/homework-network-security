#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

#define MAC_STR_SIZE 18
#define IP_STR_SIZE 16
#define MESSAGE_BUFF_SIZE 1024

/**
 * 바이트 배열로 저장된 MAC주소를 문자열(ex "ff:ff:ff:ff:ff:ff")로 변환
 * 
 * [param]
 * target: 주소가 저장될 문자열 포인터
 * addr: MAC주소가 저장된 바이트 배열
*/
void eth_mtoa(char* target, u_char addr[]) {
    char mac_addr[MAC_STR_SIZE];
    snprintf(mac_addr, MAC_STR_SIZE, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    strncpy(target, mac_addr, MAC_STR_SIZE);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
    // 분석할 정보들...
    const char buffer[MESSAGE_BUFF_SIZE]; // 응용 계층으로 전달되고자한 데이터
    char eth_src[MAC_STR_SIZE]; // Ethernet Source Address
    char eth_dst[MAC_STR_SIZE]; // Ethernet Destination Address
    char ip_src[IP_STR_SIZE]; // IP Source Address
    char ip_dst[IP_STR_SIZE]; // IP Destination Address
    u_short tcp_src; // Source Port
    u_short tcp_dst; // Destination Port

    memset((char*)buffer, 0, MESSAGE_BUFF_SIZE);
    memset((char*)eth_src, 0, MAC_STR_SIZE);
    memset((char*)eth_dst, 0, MAC_STR_SIZE);
    memset((char*)ip_src, 0, IP_STR_SIZE);
    memset((char*)ip_dst, 0, IP_STR_SIZE);

    // [1] Extract Ethernet Address
    struct ethheader *eth = (struct ethheader *)packet;
    eth_mtoa(eth_src, eth->ether_shost);
    eth_mtoa(eth_dst, eth->ether_dhost);

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        // [2] Extract IP Address
        struct ipheader * ip = (struct ipheader *) (packet + sizeof(struct ethheader));
        strncpy(ip_src, inet_ntoa(ip->iph_sourceip), IP_STR_SIZE);
        strncpy(ip_dst, inet_ntoa(ip->iph_destip), IP_STR_SIZE);
        int ip_header_len = ip->iph_ihl * 4; // IP Header Length
        unsigned short ip_payload_len = ntohs(ip->iph_len) - ip_header_len; // IP Payload Length = Total Length - IP Header Length

        /* determine protocol */
        switch(ip->iph_protocol) {
            case IPPROTO_TCP:
                // [3] Extract TCP Address
                struct tcpheader* tcp = (struct tcpheader *) ((u_char *)ip + ip_header_len);
                tcp_src = ntohs(tcp->tcp_sport);
                tcp_dst = ntohs(tcp->tcp_dport);
                int tcp_header_len = TH_OFF(tcp) * 4; // TCP Header Length
                char *data = (char *)tcp + tcp_header_len; // TCP Payload
                int data_len = ip_payload_len - tcp_header_len; // TCP Payload Length = Total Length - TCP Header Length

                // [4] Extract TCP Payload, Message
                int max_len = data_len >= MESSAGE_BUFF_SIZE ? MESSAGE_BUFF_SIZE - 1 : data_len;
                memcpy((char*)buffer, data, max_len);

                // [4] Print Packet analyze result
                printf("---------------TCP Packet caught!!---------------\n");
                printf("[Ethernet] Source MAC: %s\n", eth_src);
                printf("[Ethernet] Destination MAC: %s\n", eth_dst);
                printf("\n");
                printf("[IP] Source IP: %s\n", ip_src);
                printf("[IP] Destination IP: %s\n", ip_dst);
                printf("\n");
                printf("[TCP] Source Port: %hu\n", tcp_src);
                printf("[TCP] Destination Port: %hu\n", tcp_dst);
                printf("\n");
                printf("Message Length: %ld\n", strlen(buffer));
                printf("Message: %s\n", buffer);
                printf("\n");
                return;
            default:
                printf("------------None-TCP Packet caught!!------------\n");
                printf("\n");
                return;
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;
    
    // Step 1: Open live pcap session on NIC with name eth0
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}


