//规划好一个解包方法
//这个项目还有vlan解析没有写，以后再安排，目前可以直接套用windows中写好的代码，并且头文件需要声明一遍
#include<stdio.h>
#include<pcap.h>
#include<string.h>
#include<stdlib.h>
#include"sniff.h"
//这个包进入方法分析后，首先检查其eth_type
void eth_analyze(u_char *packet_buffer,const u_char *pkt_data,u_int pkt_len){
    struct ethheader *eth=malloc(sizeof(struct ethheader));
    memcpy(eth,pkt_data,sizeof(struct ethheader));
    if(ntohl(eth->ether_type)==0x800){
        ip_analyze(packet_buffer,pkt_data,pkt_len,(u_char *)eth,14);
    }else if(ntohl(eth->ether_type)==0x806){
        arp_analyze(packet_buffer,pkt_data,pkt_len,(u_char *)eth,14);
    }else if(ntohl(eth->ether_type)==0x86DD){   
        ipv6_analyze(packet_buffer,pkt_data,pkt_len,(u_char *)eth,14);
    }
}
void arp_analyze(u_char *packet_buffer,const u_char *pkt_data,u_int pkt_len,u_char *eth1,u_int eth_len){
    if(eth_len==14){
        struct ethheader *eth=(struct ethheader*)eth1;
        packet_args *param1=(packet_args *)packet_buffer;
        arp_packet *arp_packet1=(arp_packet*)(param1->packet_buffer);
        param1->packet_type=ARP;
        struct arpheader *arp=malloc(sizeof(struct arpheader));
        memcpy(arp,pkt_data+eth_len,sizeof(struct arpheader));
        u_char *raw_data=malloc(pkt_len);
        memcpy(raw_data,pkt_data,pkt_len);
        arp_packet1->arp=arp;
        arp_packet1->eth=eth;
        arp_packet1->raw_data=raw_data;
        arp_packet1->raw_length=pkt_len;
    }else if(eth_len==18){
        struct ethheader_vlan *eth=(struct ethheader_vlan*)eth1;
        packet_args *param1=(packet_args *)packet_buffer;
        arp_packet_vlan *arp_packet1=(arp_packet_vlan*)(param1->packet_buffer);
        param1->packet_type=ARP_VLAN;
        struct arpheader *arp=malloc(sizeof(struct arpheader));
        memcpy(arp,pkt_data+eth_len,sizeof(struct arpheader));
        u_char *raw_data=malloc(pkt_len);
        memcpy(raw_data,pkt_data,pkt_len);
        arp_packet1->arp=arp;
        arp_packet1->eth=eth;
        arp_packet1->raw_data=raw_data;
        arp_packet1->raw_length=pkt_len;
    }
}
void vlan_eth_analyze(u_char *packet_buffer,const u_char *pkt_data,u_int pkt_len){
    struct ethheader_vlan *eth=malloc(sizeof(struct ethheader_vlan));
    memcpy(eth,pkt_data,sizeof(struct ethheader_vlan));
    if(ntohl(eth->ether_type)==0x800){
        ip_analyze(packet_buffer,pkt_data,pkt_len,(u_char *)eth,18);
    }else if(ntohl(eth->ether_type)==0x806){
        arp_analyze(packet_buffer,pkt_data,pkt_len,(u_char *)eth,18);
    }else if(ntohl(eth->ether_type)==0x86DD){   
        ipv6_analyze(packet_buffer,pkt_data,pkt_len,(u_char *)eth,18);
    }

}
void ip_analyze(u_char *packet_buffer,const u_char *pkt_data,u_int pkt_len,u_char *eth1,u_int eth_len){
    packet_args *param=(packet_args*)packet_buffer;
    if(eth_len==14){
        struct ethheader *eth=(struct ethheader*)eth1;
        struct ipheader *ip=malloc(sizeof(struct ipheader));
        memcpy(ip,pkt_data+eth_len,sizeof(struct ipheader));
        u_short temp2=ntohs(((u_short *)(pkt_data+eth_len+6))[0]);
        ip->iph_offset=(temp2<<3)>>3;
        ip->iph_flag=(temp2>>13);
        u_int ip_option_length=(ip->iph_ihl-5)*4;
        u_char *ip_opt=malloc(ip_option_length);
        memcpy(ip_opt,pkt_data+eth_len+sizeof(struct ipheader),ip_option_length);
        u_char *raw_data=malloc(pkt_len);
        memcpy(raw_data,pkt_data,pkt_len);
        switch (ip->iph_protocol)
        {
        case IPPROTO_TCP:
            param->packet_type=IPV4_TCP;
            struct tcpheader *tcp=malloc(sizeof(struct tcpheader));
            tcp_analyze(tcp,pkt_data,eth_len,(ip->iph_ihl*4));
            u_int tcp_opt_len=(tcp->Data_Offset-5)*4;
            u_char *tcp_opt=malloc(tcp_opt_len);
            memcpy(tcp_opt,pkt_data+eth_len+sizeof(struct ipheader)+ip_option_length+sizeof(struct tcpheader),tcp_opt_len);
            u_int data_len1=pkt_len-eth_len-(ip->iph_ihl*4)-(tcp->Data_Offset*4);
            u_char *data1=malloc(data_len1);
            memcpy(data1,pkt_data+eth_len+(ip->iph_ihl*4)+(tcp->Data_Offset*4),data_len1);  
            tcp_packet *tcp_packet1=(tcp_packet*)(param->packet_buffer);
            tcp_packet1->eth=eth;
            tcp_packet1->ip=ip;
            tcp_packet1->ip_option=ip_opt;
            tcp_packet1->tcp=tcp;
            tcp_packet1->tcp_option=tcp_opt;
            tcp_packet1->data=data1;
            tcp_packet1->raw_length=pkt_len;
            tcp_packet1->raw_data=raw_data;
            break;
        case IPPROTO_UDP:
            param->packet_type=IPV4_UDP;
            struct udpheader *udp=malloc(sizeof(struct udpheader));
            udp_analyze(udp,pkt_data,eth_len,(ip->iph_ihl*4));
            u_int data_len2=pkt_len-eth_len-(ip->iph_ihl*4)-sizeof(struct udpheader);
            u_char *data2=malloc(data_len2);
            memcpy(data2,pkt_data+eth_len+(ip->iph_ihl*4)+sizeof(struct udpheader),data_len2);
            udp_packet *udp_packet1=(udp_packet*)(param->packet_buffer);
            udp_packet1->eth=eth;
            udp_packet1->ip=ip;
            udp_packet1->ip_option=ip_opt;
            udp_packet1->udp=udp;
            udp_packet1->data=data2;
            udp_packet1->raw_data=raw_data;
            udp_packet1->raw_length=pkt_len;
            break;
        case IPPROTO_ICMP:
            param->packet_type=IPV4_ICMP;
            struct icmpheader *icmp=malloc(sizeof(struct icmpheader));
            icmp_analyze(icmp,pkt_data,eth_len,(ip->iph_len*4));

            u_int data_len3=pkt_len-eth_len-(ip->iph_len*4);
            u_char *data3=malloc(data_len3);
            memcpy(data3,pkt_data+eth_len+(ip->iph_len)+sizeof(struct icmpheader),data_len3);
            icmp_packet *icmp_packet1=(icmp_packet*)(param->packet_buffer);
            icmp_packet1->data=data3;
            icmp_packet1->eth=eth;
            icmp_packet1->ip=ip;
            icmp_packet1->ip_option=ip_opt;
            icmp_packet1->icmp=icmp;
            icmp_packet1->raw_data=raw_data;
            icmp_packet1->raw_length=pkt_len;
            break;
        default:
            break;
        }
    }else if(eth_len==18){
        struct ethheader_vlan *eth=(struct ethheader_vlan*)eth1;
        struct ipheader *ip=malloc(sizeof(struct ipheader));
        memcpy(ip,pkt_data+eth_len,sizeof(struct ipheader));
        u_short temp2=ntohs(((u_short *)(pkt_data+eth_len+6))[0]);
        ip->iph_offset=(temp2<<3)>>3;
        ip->iph_flag=(temp2>>13);
        u_int ip_option_length=(ip->iph_ihl-5)*4;
        u_char *ip_opt=malloc(ip_option_length);
        memcpy(ip_opt,pkt_data+eth_len+sizeof(struct ipheader),ip_option_length);
        u_char *raw_data=malloc(pkt_len);
        memcpy(raw_data,pkt_data,pkt_len);
        switch (ip->iph_protocol)
        {
        case IPPROTO_TCP:
            param->packet_type=IPV4_TCP_VLAN;
            struct tcpheader *tcp=malloc(sizeof(struct tcpheader));
            tcp_analyze(tcp,pkt_data,eth_len,(ip->iph_ihl*4));
            u_int tcp_opt_len=(tcp->Data_Offset-5)*4;
            u_char *tcp_opt=malloc(tcp_opt_len);
            memcpy(tcp_opt,pkt_data+eth_len+sizeof(struct ipheader)+ip_option_length+sizeof(struct tcpheader),tcp_opt_len);
            u_int data_len1=pkt_len-eth_len-(ip->iph_ihl*4)-(tcp->Data_Offset*4);
            u_char *data1=malloc(data_len1);
            memcpy(data1,pkt_data+eth_len+(ip->iph_ihl*4)+(tcp->Data_Offset*4),data_len1);

            tcp_packet_vlan *tcp_packet1=(tcp_packet_vlan*)(param->packet_buffer);
            tcp_packet1->eth=eth;
            tcp_packet1->ip=ip;
            tcp_packet1->ip_option=ip_opt;
            tcp_packet1->tcp=tcp;
            tcp_packet1->tcp_option=tcp_opt;
            tcp_packet1->data=data1;
            tcp_packet1->raw_length=pkt_len;
            tcp_packet1->raw_data=raw_data;
            break;
        case IPPROTO_UDP:
            param->packet_type=IPV4_UDP_VLAN;
            struct udpheader *udp=malloc(sizeof(struct udpheader));
            udp_analyze(udp,pkt_data,eth_len,(ip->iph_ihl*4));
            u_int data_len2=pkt_len-eth_len-(ip->iph_ihl*4)-sizeof(struct udpheader);
            u_char *data2=malloc(data_len2);
            memcpy(data2,pkt_data+eth_len+(ip->iph_ihl*4)+sizeof(struct udpheader),data_len2);
            udp_packet_vlan *udp_packet1=(udp_packet_vlan*)(param->packet_buffer);
            udp_packet1->eth=eth;
            udp_packet1->ip=ip;
            udp_packet1->ip_option=ip_opt;
            udp_packet1->udp=udp;
            udp_packet1->data=data2;
            udp_packet1->raw_data=raw_data;
            udp_packet1->raw_length=pkt_len;
            break;
        case IPPROTO_ICMP:
            param->packet_type=IPV4_ICMP_VLAN;
            struct icmpheader *icmp=malloc(sizeof(struct icmpheader));
            icmp_analyze(icmp,pkt_data,eth_len,(ip->iph_len*4));

            u_int data_len3=pkt_len-eth_len-(ip->iph_len*4);
            u_char *data3=malloc(data_len3);
            memcpy(data3,pkt_data+eth_len+(ip->iph_len)+sizeof(struct icmpheader),data_len3);
            icmp_packet_vlan *icmp_packet1=(icmp_packet_vlan*)(param->packet_buffer);
            icmp_packet1->data=data3;
            icmp_packet1->eth=eth;
            icmp_packet1->ip=ip;
            icmp_packet1->ip_option=ip_opt;
            icmp_packet1->icmp=icmp;
            icmp_packet1->raw_data=raw_data;
            icmp_packet1->raw_length=pkt_len;
            break;
        default:
            break;
        }
    }
    
}
void ipv6_analyze(u_char *packet_buffer,const u_char *pkt_data,u_int pkt_len,u_char *eth1,u_int eth_len){
    packet_args *param=(packet_args*)packet_buffer;
    if(eth_len==14){
        struct ethheader *eth=(struct ethheader*)eth1;
        struct ipv6header *ipv6=malloc(sizeof(struct ipv6header));
        memcpy(ipv6,pkt_data+eth_len,sizeof(struct ipv6header));
        u_char *raw_data=malloc(pkt_len);
        memcpy(raw_data,pkt_data,pkt_len);
        u_int ipv6_len=sizeof(struct ipv6header);
        switch (ipv6->iph_nexthdr)
        {
        case IPPROTO_TCP:{
            struct tcpheader *tcp=malloc(sizeof(struct tcpheader));
            param->packet_type=IPV6_TCP;
            tcp_analyze(tcp,pkt_data,eth_len,ipv6_len);
            u_int tcp_opt_len=(tcp->Data_Offset-5)*4;
            u_char *tcp_opt=malloc(tcp_opt_len);
            memcpy(tcp_opt,pkt_data+eth_len+ipv6_len+sizeof(struct tcpheader),tcp_opt_len);
            u_int data_len1=pkt_len-eth_len-ipv6_len-(tcp->Data_Offset*4);
            u_char *data1=malloc(data_len1);
            memcpy(data1,pkt_data+eth_len+ipv6_len+(tcp->Data_Offset*4),data_len1);
            tcp_ipv6_packet *tcp_ipv6_packet1=(tcp_ipv6_packet*)(param->packet_buffer);
            tcp_ipv6_packet1->data=data1;
            tcp_ipv6_packet1->eth=eth;
            tcp_ipv6_packet1->ip=ipv6;
            tcp_ipv6_packet1->tcp=tcp;
            tcp_ipv6_packet1->tcp_option=tcp_opt;
            tcp_ipv6_packet1->raw_data=raw_data;
            tcp_ipv6_packet1->raw_length=pkt_len;
            break;}
        case IPPROTO_UDP:{
            param->packet_type=IPV6_UDP;
            struct udpheader *udp=malloc(sizeof(struct udpheader));
            udp_analyze(udp,pkt_data,eth_len,ipv6_len);
            u_int data_len=pkt_len-eth_len-ipv6_len-sizeof(struct udpheader);
            u_char *data1=malloc(data_len);
            memcpy(data1,pkt_data+eth_len+ipv6_len+sizeof(struct udpheader),data_len);
            udp_ipv6_packet *udp_ipv6_packet1=(udp_ipv6_packet*)(param->packet_buffer);
            udp_ipv6_packet1->data=data1;
            udp_ipv6_packet1->eth=eth;
            udp_ipv6_packet1->ip=ipv6;
            udp_ipv6_packet1->raw_data=raw_data;
            udp_ipv6_packet1->raw_length=pkt_len;
            udp_ipv6_packet1->udp=udp;
            break;}
        case IPPROTO_ICMP:{
            param->packet_type=IPV6_ICMP;
            struct icmpheader *icmp=malloc(sizeof(struct icmpheader));
            icmp_analyze(icmp,pkt_data,eth_len,ipv6_len);

            u_int data_len=pkt_len-eth_len-ipv6_len;
            u_char *data1=malloc(data_len);
            memcpy(data1,pkt_data+eth_len+ipv6_len+sizeof(struct icmpheader),data_len);
        
            icmp_ipv6_packet *icmp_ipv6_packet1=(icmp_ipv6_packet*)(param->packet_buffer);
            icmp_ipv6_packet1->data=data1;
            icmp_ipv6_packet1->eth=eth;
            icmp_ipv6_packet1->ip=ipv6;
            icmp_ipv6_packet1->raw_data=raw_data;
            icmp_ipv6_packet1->raw_length=pkt_len;
            break;}
        default:
            break;
        }
    }else if(eth_len==18){
        struct ethheader_vlan *eth=(struct ethheader_vlan*)eth1;
        struct ipv6header *ipv6=malloc(sizeof(struct ipv6header));
        memcpy(ipv6,pkt_data+eth_len,sizeof(struct ipv6header));
        u_char *raw_data=malloc(pkt_len);
        memcpy(raw_data,pkt_data,pkt_len);
        u_int ipv6_len=sizeof(struct ipv6header);
        switch (ipv6->iph_nexthdr)
        {
        case IPPROTO_TCP:{
            param->packet_type=IPV6_TCP_VLAN;
            struct tcpheader *tcp=malloc(sizeof(struct tcpheader));
            
            tcp_analyze(tcp,pkt_data,eth_len,ipv6_len);
            u_int tcp_opt_len=(tcp->Data_Offset-5)*4;
            u_char *tcp_opt=malloc(tcp_opt_len);
            memcpy(tcp_opt,pkt_data+eth_len+ipv6_len+sizeof(struct tcpheader),tcp_opt_len);
            u_int data_len=pkt_len-eth_len-ipv6_len-(tcp->Data_Offset*4);
            u_char *data1=malloc(data_len);
            memcpy(data1,pkt_data+eth_len+ipv6_len+(tcp->Data_Offset*4),data_len);
            tcp_ipv6_packet_vlan *tcp_ipv6_packet1=(tcp_ipv6_packet_vlan*)(param->packet_buffer);
            tcp_ipv6_packet1->data=data1;
            tcp_ipv6_packet1->eth=eth;
            tcp_ipv6_packet1->ip=ipv6;
            tcp_ipv6_packet1->tcp=tcp;
            tcp_ipv6_packet1->tcp_option=tcp_opt;
            tcp_ipv6_packet1->raw_data=raw_data;
            tcp_ipv6_packet1->raw_length=pkt_len;
            break;}
        case IPPROTO_UDP:{
            param->packet_type=IPV6_UDP_VLAN;
            struct udpheader *udp=malloc(sizeof(struct udpheader));
            udp_analyze(udp,pkt_data,eth_len,ipv6_len);
            u_int data_len=pkt_len-eth_len-ipv6_len-sizeof(struct udpheader);
            u_char *data1=malloc(data_len);
            memcpy(data1,pkt_data+eth_len+ipv6_len+sizeof(struct udpheader),data_len);
            udp_ipv6_packet_vlan *udp_ipv6_packet1=(udp_ipv6_packet_vlan*)(param->packet_buffer);
            udp_ipv6_packet1->data=data1;
            udp_ipv6_packet1->eth=eth;
            udp_ipv6_packet1->ip=ipv6;
            udp_ipv6_packet1->udp=udp;
            udp_ipv6_packet1->raw_data=raw_data;
            udp_ipv6_packet1->raw_length=pkt_len;
            break;}
        case IPPROTO_ICMP:{
            param->packet_type=IPV6_ICMP_VLAN;
            struct icmpheader *icmp=malloc(sizeof(struct icmpheader));
            icmp_analyze(icmp,pkt_data,eth_len,ipv6_len);

            u_int data_len=pkt_len-eth_len-ipv6_len;
            u_char *data1=malloc(data_len);
            memcpy(data1,pkt_data+eth_len+ipv6_len+sizeof(struct icmpheader),data_len);
        
            icmp_ipv6_packet_vlan *icmp_ipv6_packet1=(icmp_ipv6_packet_vlan*)(param->packet_buffer);
            icmp_ipv6_packet1->data=data1;
            icmp_ipv6_packet1->eth=eth;
            icmp_ipv6_packet1->ip=ipv6;
            icmp_ipv6_packet1->icmp=icmp;
            icmp_ipv6_packet1->raw_data=raw_data;
            icmp_ipv6_packet1->raw_length=pkt_len;
            break;}
        default:
            break;
        }
    }
    

}

void tcp_analyze(struct tcpheader *tcp,const u_char *pkt_data,u_int eth_len,u_int ip_len){
    memcpy(tcp,pkt_data+eth_len+ip_len,sizeof(struct tcpheader));
    u_short temps=ntohs(((u_short *)(pkt_data+eth_len+ip_len+12))[0]);
    tcp->Data_Offset=(temps>>12);
    tcp->reserved=(temps<<4)>>10;
    tcp->control_flags=(temps<<10)>>10;
}
void udp_analyze(struct udpheader *udp,const u_char *pkt_data,u_int eth_len,u_int ip_len){
    memcpy(udp,pkt_data+eth_len+ip_len,sizeof(struct udpheader));
}
void icmp_analyze(struct icmpheader *icmp,const u_char *pkt_data,u_int eth_len,u_int ip_len){
    memcpy(icmp,pkt_data+eth_len+ip_len,sizeof(struct icmpheader));
}
void packet_analyze(u_char *user_arg,const struct pcap_pkthdr *header, const u_char *pkt_data){
    packet_args *args=(packet_args *)user_arg;
    args->packet_length=header->caplen;
    struct ethheader *temp_eth=malloc(sizeof(struct ethheader));
    memcpy(temp_eth,pkt_data,14);
    if(ntohs(temp_eth->ether_type) == 0x8100 || ntohs(temp_eth->ether_type) == 0x88A8){
        free(temp_eth);
        vlan_eth_analyze(user_arg,pkt_data,header->caplen);
    }else{
        free(temp_eth);
        eth_analyze(user_arg,pkt_data,header->caplen);
    }   
    

}