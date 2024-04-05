#include "packet_constructor.h"
#define dest_ip "192.168.1.113"
#define dest_port 1
int main(){
    u_char *buffer=malloc(1500);
    struct ipheader ip;
    struct tcpheader tcp;


    srand(time(0));
    int flag=1;
    while(flag){
    memset(&ip,0,sizeof(struct ipheader));
    memset(&tcp,0,sizeof(struct tcpheader));
    ip.iph_ver=4;
    ip.iph_ihl=5;
    ip.iph_ttl=200;
    ip.iph_len=htons(sizeof(struct ipheader)+sizeof(struct tcpheader));
    ip.iph_protocol=IPPROTO_TCP;
    ip.iph_sourceip.s_addr=rand();
    ip.iph_destip.s_addr=inet_addr(dest_ip);


    tcp.th_sport=htons(rand()%60000+1024);
    tcp.th_dport=htons(dest_port);
    tcp.th_seq=rand();
    tcp.Data_Offset=5;
    tcp.control_flags=2;//SYN
    tcp.th_win=htons(20000);
    tcp.th_sum=0;
    htonipheader(&ip);
    htontcpheader(&tcp);
    calculate_tcp_cheksum(&ip,&tcp,NULL,0,NULL,0);
    int lenth=20;
    ip.iph_chksum=calculate_checksum((u_int8_t *)&ip,lenth);
    raw_packet_constructor(IPV4_TCP,buffer,1500,(u_char*)&ip,NULL,0,(u_char *)&tcp,NULL,0,NULL,0);
    send_raw_packet(buffer,40,&ip);
    flag=0;
    }
    free(buffer);
}
