#include<stdio.h>
#include<winsock2.h>
#include <windows.h>
#include <pcap.h>

#define buffer_size 3096
//请注意,mac头部不包含在构建包中，也许mac头部交给操作系统去填充
void construct_raw_udp_packet(struct ipheader *ip_1,u_char *ip_opt,u_int ip_opt_len,struct udpheader *udp1,u_char *buffer_packet,u_int BUFFER_SIZE,u_char *data2);
void construct_raw_tcp_packet(struct ipheader *ip_1,u_char *ip_opt,u_int ip_opt_len,struct tcpheader *tcp1,u_char tcp_opt,u_int tcp_opt_len,u_char *buffer_packet,u_int BUFFER_SIZE,u_char *data2);
void construct_raw_icmp_packet(struct ipheader *ip_1,u_char *ip_opt,u_int ip_opt_len,struct icmpheader *icmp1,u_char *buffer_packet,u_int BUFFER_SIZE,u_char *data2);
void calculate_tcp_cheksum(struct ipheader *ip,struct tcpheader *tcp,u_char *tcp_opt,u_int tcp_opt_len,u_char *data,u_int data_len);
void send_raw_packet(u_char *buffer_packet,u_int length,struct ipheader *ip);
u_int get_ip_option_length(struct ipheader *ip);
u_int get_tcp_option_length(struct tcpheader *tcp);
void htonipheader(struct ipheader *ip);
void htontcpheader(struct tcpheader *tcp);
