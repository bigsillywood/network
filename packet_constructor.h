#include"header_structure.h"
u_int get_ip_option_length(struct ipheader *ip);
u_int get_tcp_option_length(struct tcpheader *tcp);
void htonipheader(struct ipheader *ip);
void htontcpheader(struct tcpheader *tcp);
uint16_t calculate_checksum(uint8_t *buffer, size_t length);
void calculate_tcp_cheksum(struct ipheader *ip,struct tcpheader *tcp,u_char *tcp_opt,u_int tcp_opt_len,u_char *data,u_int data_len);
int raw_packet_constructor(u_int type,u_char *buffer,u_int buffer_size,u_char *i_head,u_char *i_opt,u_int i_opt_len,u_char *a_head,u_char *a_opt,u_int a_opt_len,u_char *data,u_int data_len);
void send_raw_packet(u_char *buffer_packet,u_int length,struct ipheader *ip);