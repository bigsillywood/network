#include"header_structure.h"

void eth_analyze(u_char *packet_buffer,const u_char *pkt_data,u_int pkt_len);
void arp_analyze(u_char *packet_buffer,const u_char *pkt_data,u_int pkt_len,u_char *eth1,u_int eth_len);
void vlan_eth_analyze(u_char *packet_buffer,const u_char *pkt_data,u_int pkt_len);
void ip_analyze(u_char *packet_buffer,const u_char *pkt_data,u_int pkt_len,u_char *eth1,u_int eth_len);
void ipv6_analyze(u_char *packet_buffer,const u_char *pkt_data,u_int pkt_len,u_char *eth1,u_int eth_len);
void tcp_analyze(struct tcpheader *tcp,const u_char *pkt_data,u_int eth_len,u_int ip_len);
void udp_analyze(struct udpheader *udp,const u_char *pkt_data,u_int eth_len,u_int ip_len);
void icmp_analyze(struct icmpheader *icmp,const u_char *pkt_data,u_int eth_len,u_int ip_len);
void packet_analyze(u_char *user_arg,const struct pcap_pkthdr *header, const u_char *pkt_data);