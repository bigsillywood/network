#include<stdio.h>
#include <pcap/pcap.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "header_structure.h"
#include "raw_packet_constructor.h"


//捕获并解析数据包
void got_pack(u_char *param1, const struct pcap_pkthdr *header, const u_char *pkt_data){
    printf("数据包长度: %d\n", header->caplen);
    for(int i=0;i<header->caplen;i++){
        printf("%02x ",pkt_data[i]);
        if((i+1)%16==0){
            printf("\n");
        }
    }
    packet_args *param=(packet_args *)param1;
    param->packet_length=header->caplen;
    printf("数据包捕获成功\n");
    u_char *raw_data=(u_char *)malloc(header->caplen);
    memcpy(raw_data,pkt_data,header->caplen);
    //这里的pkt_data是一个指向数据包的指针，此解析涉及到头部长度的问题，所以需要用指针来解析
    struct ethheader *ethernet=(struct ethheader *)pkt_data;
    if(ntohs(ethernet->ether_type)==0x800){
        printf("IP数据包\n");
        //复制保存以太网头部
        struct ethheader *eth=(struct ethheader *)malloc(sizeof(struct ethheader));
        memcpy(eth,pkt_data,sizeof(struct ethheader));
        //复制保存IP头部
        struct ipheader *ip=(struct ipheader *)malloc(sizeof(struct ipheader));
        memcpy(ip,pkt_data+sizeof(struct ethheader),sizeof(struct ipheader));
        
        u_short temp2=ntohs(((u_short *)(pkt_data+sizeof(struct ethheader)+6))[0]);
        ip->iph_offset=(temp2<<3)>>3;
        ip->iph_flag=(temp2>>13);

        int ip_option_length=(ip->iph_ihl-5)*4;
        printf("IP头部选项长度:%d\n",ip_option_length);
        printf("IP头部长度:%d\n",ip->iph_ihl*4);
        printf("IP头部版本:%d\n",ip->iph_ver);
        //复制保存IP选项
        u_char *ip_option=(u_char *)malloc(ip_option_length);
        memcpy(ip_option,pkt_data+sizeof(struct ethheader)+sizeof(struct ipheader),ip_option_length);
        printf("源IP地址:%s\n",inet_ntoa(ip->iph_sourceip));
        printf("目的IP地址:%s\n",inet_ntoa(ip->iph_destip));
        
        switch (ip->iph_protocol)
        {
        case IPPROTO_TCP:
            printf("TCP协议\n");
            //复制保存TCP头部
            struct tcpheader *tcp=(struct tcpheader *)malloc(sizeof(struct tcpheader));
            memcpy(tcp,pkt_data+sizeof(struct ethheader)+sizeof(struct ipheader)+ip_option_length,sizeof(struct tcpheader));
            //复制保存TCP选项
            printf("源端口:%d\n",ntohs(tcp->th_sport));
            printf("目的端口:%d\n",ntohs(tcp->th_dport));
            printf("TCP头部保存成功\n");
            /*printf("TCP头部长度:%d\n",tcp->Data_Offset);*/
            
            u_short temps=ntohs(((u_short *)(pkt_data+sizeof(struct ethheader)+sizeof(struct ipheader)+ip_option_length+12))[0]);
            printf("TCP13位到16位:%02x\n",(temps));
            tcp->Data_Offset=(temps>>12);
            tcp->reserved=(temps<<4)>>10;
            tcp->control_flags=(temps<<10)>>10;
            u_short tcp_option_length=(tcp->Data_Offset-5)*4;
            u_char *tcp_option=(u_char *)malloc(tcp_option_length);
            printf("TCP选项长度:%d\n",tcp_option_length);

            memcpy(tcp_option,pkt_data+sizeof(struct ethheader)+sizeof(struct ipheader)+ip_option_length+sizeof(struct tcpheader),tcp_option_length);
            //复制保存处理好的数据
            u_char *data1=(u_char *)malloc(header->caplen-sizeof(struct ethheader)-sizeof(struct ipheader)-ip_option_length-sizeof(struct tcpheader)-tcp_option_length);
            memcpy(data1,pkt_data+sizeof(struct ethheader)+sizeof(struct ipheader)+ip_option_length+sizeof(struct tcpheader)+tcp_option_length,header->caplen-sizeof(struct ethheader)-sizeof(struct ipheader)-ip_option_length-sizeof(struct tcpheader)-tcp_option_length);
            
            
            tcp_packet *tcp_pack=(tcp_packet *)(param->packet_buffer);
            tcp_pack->raw_data=raw_data;
            tcp_pack->raw_length=header->caplen;
            tcp_pack->eth=eth;
            tcp_pack->ip=ip;
            tcp_pack->ip_option=ip_option;
            tcp_pack->tcp=tcp;
            tcp_pack->tcp_option=tcp_option;
            tcp_pack->data=data1;
            param->packet_type=IPV4_TCP;
            int data_length1=(int)(header->caplen-sizeof(struct ethheader)-sizeof(struct ipheader)-ip_option_length-sizeof(struct tcpheader)-tcp_option_length);
            if(data_length1>0){
                for (int i = 0; i < data_length1; i++)
                {
                    printf("%02x ",data1[i]);
                }
                
                printf("转换为字符串为:%s\n",data1);
            }else{
                printf("数据为空\n");
            }
            break;
        case IPPROTO_UDP:
            struct udpheader *udp=(struct udpheader *)malloc(sizeof(struct udpheader));
            memcpy(udp,pkt_data+sizeof(struct ethheader)+sizeof(struct ipheader)+ip_option_length,sizeof(struct udpheader));

            u_char *data2=(u_char *)malloc(header->caplen-sizeof(struct ethheader)-sizeof(struct ipheader)-ip_option_length-sizeof(struct udpheader));
            memcpy(data2,pkt_data+sizeof(struct ethheader)+sizeof(struct ipheader)+ip_option_length+sizeof(struct udpheader),header->caplen-sizeof(struct ethheader)-sizeof(struct ipheader)-ip_option_length-sizeof(struct udpheader));
            
            udp_packet *udp_pack=(udp_packet *)(param->packet_buffer);
            udp_pack->raw_data=raw_data;
            udp_pack->raw_length=header->caplen;
            udp_pack->eth=eth;
            udp_pack->ip=ip;
            udp_pack->ip_option=ip_option;
            udp_pack->udp=udp;
            udp_pack->data=data2;
            param->packet_type=IPV4_UDP;
            printf("UDP协议\n");
            printf("源端口:%d\n",ntohs(udp->uh_sport));
            printf("目的端口:%d\n",ntohs(udp->uh_dport));
            int data_length2=(int)(header->caplen-sizeof(struct ethheader)-sizeof(struct ipheader)-ip_option_length-sizeof(struct udpheader));
            if(data_length2>0){
                for (int i = 0; i < data_length2; i++)
                {
                    printf("%02x ",data2[i]);
                }
                
                printf("转换为字符串为:%s\n",data2);
            }else{
                printf("数据为空\n");
            }
            return;
            break;
        case IPPROTO_ICMP:
            printf("ICMP协议开始解析\n");
        //对于ICMP，解析并不完善，最好查看IP头部的长度，然后再解析ICMP头部
            struct icmpheader *icmp=(struct icmpheader *)malloc(sizeof(struct icmpheader));
            memcpy(icmp,pkt_data+sizeof(struct ethheader)+sizeof(struct ipheader)+ip_option_length,sizeof(struct icmpheader));

            u_char *data3=(u_char *)malloc(header->caplen-sizeof(struct ethheader)-sizeof(struct ipheader)-ip_option_length-sizeof(struct icmpheader));
            memcpy(data3,pkt_data+sizeof(struct ethheader)+sizeof(struct ipheader)+ip_option_length+sizeof(struct icmpheader),header->caplen-sizeof(struct ethheader)-sizeof(struct ipheader)-ip_option_length-sizeof(struct icmpheader));
            printf("内存复制完毕\n");
            //此数据包含icmp头部的一部分，一般来说还需要后移动4个字节才是真正的数据，不过由于icmp可变性较大，所以这里不做处理
            //此段开始有bug，导致后续没法跑，需要修改
            icmp_packet *icmp_pack=(icmp_packet *)(param->packet_buffer);
            icmp_pack->raw_data=raw_data;
            icmp_pack->raw_length=header->caplen;
            icmp_pack->eth=eth;
            icmp_pack->ip=ip;
            icmp_pack->ip_option=ip_option;
            icmp_pack->icmp=icmp;
            icmp_pack->data=data3;
            param->packet_type=IPV4_ICMP;
            printf("准备打印内容\n");
            if(header->caplen-sizeof(struct ethheader)-sizeof(struct ipheader)-ip_option_length-sizeof(struct icmpheader)>0){
                printf("数据为:%02x\n",data3);
                printf("转换为字符串为:%s\n",data3);
            }else{
                printf("数据为空\n");
            }
            printf("ICMP协议\n");
            break;

        default:
            printf("未知协议\n");
            break;
        }
        return;
    }else if(ntohs(ethernet->ether_type)==0x806){
        printf("ARP数据包\n");
        struct ethheader *eth=(struct ethheader *)malloc(sizeof(struct ethheader));
        memcpy(eth,pkt_data,sizeof(struct ethheader));
        struct arpheader *arp=(struct arpheader *)malloc(sizeof(struct arpheader));
        memcpy(arp,pkt_data+sizeof(struct ethheader),sizeof(struct arpheader));
        arp_packet *arp_pack=(arp_packet *)(param->packet_buffer);
        arp_pack->raw_data=raw_data;
        arp_pack->raw_length=header->caplen;
        arp_pack->eth=eth;
        arp_pack->arp=arp;
        param->packet_type=ARP;
        printf("ARP协议\n");
        return;
    }else if(ntohs(ethernet->ether_type) == 0x8100 || ntohs(ethernet->ether_type) == 0x88A8){
        printf("VLAN数据包\n");
        struct ethheader_vlan *eth_vlan=(struct ethheader_vlan *)malloc(sizeof(struct ethheader_vlan));
        memcpy(eth_vlan,pkt_data,sizeof(struct ethheader_vlan));

        if(ntohs(eth_vlan->ether_type)==0x800){
            printf("IP数据包\n");
            struct ipheader *ip=(struct ipheader *)malloc(sizeof(struct ipheader));
            memcpy(ip,pkt_data+sizeof(struct ethheader_vlan),sizeof(struct ipheader));
        
            u_short temp2=ntohs(((u_short *)(pkt_data+sizeof(struct ethheader_vlan)+6))[0]);
            ip->iph_offset=(temp2<<3)>>3;
            ip->iph_flag=(temp2>>13);

            int ip_option_length=(ip->iph_ihl-5)*4;
            printf("IP头部选项长度:%d\n",ip_option_length);
            printf("IP头部长度:%d\n",ip->iph_ihl*4);
            printf("IP头部版本:%d\n",ip->iph_ver);
            //复制保存IP选项
            u_char *ip_option=(u_char *)malloc(ip_option_length);
            memcpy(ip_option,pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipheader),ip_option_length);
            printf("源IP地址:%s\n",inet_ntoa(ip->iph_sourceip));
            printf("目的IP地址:%s\n",inet_ntoa(ip->iph_destip));
        
            switch (ip->iph_protocol)
            {
                case IPPROTO_TCP:
                printf("TCP协议\n");
                //复制保存TCP头部
                struct tcpheader *tcp=(struct tcpheader *)malloc(sizeof(struct tcpheader));
                memcpy(tcp,pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipheader)+ip_option_length,sizeof(struct tcpheader));
                //复制保存TCP选项
                printf("源端口:%d\n",ntohs(tcp->th_sport));
                printf("目的端口:%d\n",ntohs(tcp->th_dport));
                printf("TCP头部保存成功\n");
                /*printf("TCP头部长度:%d\n",tcp->Data_Offset);*/
            
                u_short temps=ntohs(((u_short *)(pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipheader)+ip_option_length+12))[0]);
                printf("TCP13位到16位:%02x\n",(temps));
                tcp->Data_Offset=(temps>>12);
                tcp->reserved=(temps<<4)>>10;
                tcp->control_flags=(temps<<10)>>10;
                u_short tcp_option_length=(tcp->Data_Offset-5)*4;
                u_char *tcp_option=(u_char *)malloc(tcp_option_length);
                printf("TCP选项长度:%d\n",tcp_option_length);

                memcpy(tcp_option,pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipheader)+ip_option_length+sizeof(struct tcpheader),tcp_option_length);
                //复制保存处理好的数据
                u_char *data1=(u_char *)malloc(header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipheader)-ip_option_length-sizeof(struct tcpheader)-tcp_option_length);
                memcpy(data1,pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipheader)+ip_option_length+sizeof(struct tcpheader)+tcp_option_length,header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipheader)-ip_option_length-sizeof(struct tcpheader)-tcp_option_length);
            
            
                tcp_packet_vlan *tcp_pack=(tcp_packet_vlan *)(param->packet_buffer);
                tcp_pack->raw_data=raw_data;
                tcp_pack->raw_length=header->caplen;
                tcp_pack->eth=eth_vlan;
                tcp_pack->ip=ip;
                tcp_pack->ip_option=ip_option;
                tcp_pack->tcp=tcp;
                tcp_pack->tcp_option=tcp_option;
                tcp_pack->data=data1;
                param->packet_type=IPV4_TCP_VLAN;
                if(header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipheader)-ip_option_length-sizeof(struct tcpheader)-tcp_option_length>0){
                    printf("数据为:%02x\n",data1);
                    printf("转换为字符串为:%s\n",data1);
                }else{
                    printf("数据为空\n");
                }
                break;
            case IPPROTO_UDP:
                struct udpheader *udp=(struct udpheader *)malloc(sizeof(struct udpheader));
                memcpy(udp,pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipheader)+ip_option_length,sizeof(struct udpheader));

                u_char *data2=(u_char *)malloc(header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipheader)-ip_option_length-sizeof(struct udpheader));
                memcpy(data2,pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipheader)+ip_option_length+sizeof(struct udpheader),header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipheader)-ip_option_length-sizeof(struct udpheader));
            
                udp_packet_vlan *udp_pack=(udp_packet_vlan *)(param->packet_buffer);
                udp_pack->raw_data=raw_data;
                udp_pack->raw_length=header->caplen;
                udp_pack->eth=eth_vlan;
                udp_pack->ip=ip;
                udp_pack->ip_option=ip_option;
                udp_pack->udp=udp;
                udp_pack->data=data2;
                param->packet_type=IPV4_UDP_VLAN;
                printf("UDP协议\n");
                printf("源端口:%d\n",ntohs(udp->uh_sport));
                printf("目的端口:%d\n",ntohs(udp->uh_dport));
                if(header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipheader)-ip_option_length-sizeof(struct udpheader)>0){
                    printf("数据为:%02x\n",data2);
                    printf("转换为字符串为:%s\n",data2);
                }else{
                    printf("数据为空\n");
                }
                return;
                break;
            case IPPROTO_ICMP:
                printf("ICMP协议开始解析\n");
                //对于ICMP，解析并不完善，最好查看IP头部的长度，然后再解析ICMP头部
                struct icmpheader *icmp=(struct icmpheader *)malloc(sizeof(struct icmpheader));
                memcpy(icmp,pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipheader)+ip_option_length,sizeof(struct icmpheader));

                u_char *data3=(u_char *)malloc(header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipheader)-ip_option_length-sizeof(struct icmpheader));
                memcpy(data3,pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipheader)+ip_option_length+sizeof(struct icmpheader),header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipheader)-ip_option_length-sizeof(struct icmpheader));

                //此数据包含icmp头部的一部分，一般来说还需要后移动4个字节才是真正的数据，不过由于icmp可变性较大，所以这里不做处理,也就是数据中包含了icmp头部的一部分
                icmp_packet_vlan *icmp_pack=(icmp_packet_vlan *)(param->packet_buffer);
                icmp_pack->raw_data=raw_data;
                icmp_pack->raw_length=header->caplen;
                icmp_pack->eth=eth_vlan;
                icmp_pack->ip=ip;
                icmp_pack->ip_option=ip_option;
                icmp_pack->icmp=icmp;
                icmp_pack->data=data3;
                param->packet_type=IPV4_ICMP_VLAN;
                if(header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipheader)-ip_option_length-sizeof(struct icmpheader)>0){
                    printf("数据为:%02x\n",data3);
                    printf("转换为字符串为:%s\n",data3);
                }else{
                    printf("数据为空\n");
                }

                printf("ICMP协议\n");
                break;
            default:
                printf("未知协议\n");
                break;
            }
            return;
        }else if(ntohs(eth_vlan->ether_type)==0x86DD){
            printf("IPv6数据包\n");
            struct ethheader_vlan *eth=(struct ethheader_vlan *)malloc(sizeof(struct ethheader_vlan));
            memcpy(eth,pkt_data,sizeof(struct ethheader_vlan));
            struct ipv6header *ipv6=(struct ipv6header *)malloc(sizeof(struct ipv6header));
            memcpy(ipv6,pkt_data+sizeof(struct ethheader_vlan),sizeof(struct ipv6header));
            u_char str[INET6_ADDRSTRLEN];
            printf("源IP地址:%s\n",inet_ntop(AF_INET6,&(ipv6->iph_sourceip),str,buffer_size));
            printf("目的IP地址:%s\n",inet_ntop(AF_INET6,&(ipv6->iph_destip),str,buffer_size));
            switch(ipv6->iph_nexthdr){
                case IPPROTO_TCP:
                    printf("TCP协议\n");
                    struct tcpheader *tcp=(struct tcpheader *)malloc(sizeof(struct tcpheader));
                    memcpy(tcp,pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipv6header),sizeof(struct tcpheader));

                    printf("源端口:%d\n",ntohs(tcp->th_sport));
                    printf("目的端口:%d\n",ntohs(tcp->th_dport));

                    u_short temps=ntohs(((u_short *)(pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipv6header)+12))[0]);
                    printf("TCP13位到16位:%02x\n",(temps));
                    tcp->Data_Offset=(temps>>12);
                    tcp->reserved=(temps<<4)>>10;
                    tcp->control_flags=(temps<<10)>>10;
                    u_short tcp_option_length=(tcp->Data_Offset-5)*4;
                    u_char *tcp_option=(u_char *)malloc(tcp_option_length);
                    printf("TCP选项长度:%d\n",tcp_option_length);
                    memcpy(tcp_option,pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipv6header)+sizeof(struct tcpheader),tcp_option_length);    
                    u_char *data1=(u_char *)malloc(header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipv6header)-sizeof(struct tcpheader)-tcp_option_length);
                    memcpy(data1,pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipv6header)+sizeof(struct tcpheader)+tcp_option_length,header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipv6header)-sizeof(struct tcpheader)-tcp_option_length);
                    
                    tcp_packet_vlan *tcp_pack=(tcp_packet_vlan *)(param->packet_buffer);
                    tcp_pack->raw_data=raw_data;
                    tcp_pack->raw_length=header->caplen;
                    tcp_pack->eth=eth;
                    tcp_pack->ip=(struct ipheader *)ipv6;
                    tcp_pack->tcp=tcp;
                    tcp_pack->tcp_option=tcp_option;
                    tcp_pack->data=data1;
                    param->packet_type=IPV6_TCP_VLAN;
                    u_int data_length1=(u_int)(header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipv6header)-sizeof(struct tcpheader)-tcp_option_length);
                    if(data_length1>0){
                        for (int i = 0; i < data_length1; i++)
                        {
                            printf("%02x ",data1[i]);
                        }
                        printf("转换为字符串为:%s\n",data1);
                    }else{
                        printf("数据为空\n");
                    }
                    return;
                    break;
                case IPPROTO_UDP:
                    printf("UDP协议\n");
                    struct udpheader *udp=(struct udpheader *)malloc(sizeof(struct udpheader));
                    memcpy(udp,pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipv6header),sizeof(struct udpheader));

                    printf("源端口:%d\n",ntohs(udp->uh_sport));
                    printf("目的端口:%d\n",ntohs(udp->uh_dport));

                    u_char *data2=(u_char *)malloc(header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipv6header)-sizeof(struct udpheader));
                    memcpy(data2,pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipv6header)+sizeof(struct udpheader),header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipv6header)-sizeof(struct udpheader));

                    udp_packet_vlan *udp_pack=(udp_packet_vlan *)(param->packet_buffer);
                    udp_pack->raw_data=raw_data;
                    udp_pack->raw_length=header->caplen;
                    udp_pack->eth=eth;
                    udp_pack->ip=(struct ipheader *)ipv6;
                    udp_pack->udp=udp;
                    udp_pack->data=data2;
                    param->packet_type=IPV6_UDP_VLAN;
                    u_int data_length2=(u_int)(header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipv6header)-sizeof(struct udpheader));
                    if(data_length2>0){
                        for(int i=0;i<data_length2;i++){
                            printf("%02x ",data2[i]);
                        }
                        printf("转换为字符串为:%s\n",data2);
                    }else{
                        printf("数据为空\n");
                    }
                    return;
                    break;
                case IPPROTO_ICMP:
                    printf("ICMP协议\n");
                    struct icmpheader *icmp=(struct icmpheader *)malloc(sizeof(struct icmpheader));
                    memcpy(icmp,pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipv6header),sizeof(struct icmpheader));

                    u_char *data3=(u_char *)malloc(header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipv6header)-sizeof(struct icmpheader));
                    memcpy(data3,pkt_data+sizeof(struct ethheader_vlan)+sizeof(struct ipv6header)+sizeof(struct icmpheader),header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipv6header)-sizeof(struct icmpheader));

                    icmp_packet_vlan *icmp_pack=(icmp_packet_vlan *)(param->packet_buffer);
                    icmp_pack->raw_data=raw_data;
                    icmp_pack->raw_length=header->caplen;
                    icmp_pack->eth=eth;
                    icmp_pack->ip=(struct ipheader *)ipv6;
                    icmp_pack->icmp=icmp;
                    icmp_pack->data=data3;
                    param->packet_type=IPV6_ICMP_VLAN;
                    if(header->caplen-sizeof(struct ethheader_vlan)-sizeof(struct ipv6header)-sizeof(struct icmpheader)>0){
                        printf("数据为:%02x\n",data3);
                        printf("转换为字符串为:%s\n",data3);
                    }else{
                        printf("数据为空\n");
                    }
                    return;
                    break;
        }
        }else if(ntohs(eth_vlan->ether_type)==0x806){
            printf("ARP数据包\n");
            struct ethheader_vlan *eth=(struct ethheader_vlan *)malloc(sizeof(struct ethheader_vlan));
            memcpy(eth,pkt_data,sizeof(struct ethheader_vlan));
            struct arpheader *arp=(struct arpheader *)malloc(sizeof(struct arpheader));
            memcpy(arp,pkt_data+sizeof(struct ethheader_vlan),sizeof(struct arpheader));
            arp_packet_vlan *arp_pack=(arp_packet_vlan *)(param->packet_buffer);
            arp_pack->raw_data=raw_data;
            arp_pack->raw_length=header->caplen;
            arp_pack->eth=eth;
            arp_pack->arp=arp;
            param->packet_type=ARP_VLAN;
            printf("ARP协议\n");
            return;

        }else{
            printf("未知协议\n");
        }            
    }else if(ntohs(ethernet->ether_type)==0x86DD){
        printf("IPv6数据包\n");
        struct ethheader *eth=(struct ethheader *)malloc(sizeof(struct ethheader));
        memcpy(eth,pkt_data,sizeof(struct ethheader));


        struct ipv6header *ipv6=(struct ipv6header *)malloc(sizeof(struct ipv6header));
        memcpy(ipv6,pkt_data+sizeof(struct ethheader),sizeof(struct ipv6header));
        u_char str[INET6_ADDRSTRLEN];
        printf("源IP地址:%s\n",inet_ntop(AF_INET6,&(ipv6->iph_sourceip),str,buffer_size));
        printf("目的IP地址:%s\n",inet_ntop(AF_INET6,&(ipv6->iph_destip),str,buffer_size));
        
        u_int temp4=ntohl(((u_int *)(pkt_data+sizeof(struct ethheader)))[0]);
        ipv6->iph_ver=(temp4>>28);
        ipv6->iph_priority=(temp4<<4)>>28;
        ipv6->iph_flow=(temp4<<12)>>12;

        switch (ipv6->iph_nexthdr)
        {
            case IPPROTO_TCP:
                printf("TCP协议\n");
                struct tcpheader *tcp=(struct tcpheader *)malloc(sizeof(struct tcpheader));
                memcpy(tcp,pkt_data+sizeof(struct ethheader)+sizeof(struct ipv6header),sizeof(struct tcpheader));

                printf("源端口:%d\n",ntohs(tcp->th_sport));
                printf("目的端口:%d\n",ntohs(tcp->th_dport));

                u_short temps=ntohs(((u_short *)(pkt_data+sizeof(struct ethheader)+sizeof(struct ipv6header)+12))[0]);
                printf("TCP13位到16位:%02x\n",(temps));
                tcp->Data_Offset=(temps>>12);
                tcp->reserved=(temps<<4)>>10;
                tcp->control_flags=(temps<<10)>>10;
                u_short tcp_option_length=(tcp->Data_Offset-5)*4;
                u_char *tcp_option=(u_char *)malloc(tcp_option_length);
                printf("TCP选项长度:%d\n",tcp_option_length);
                memcpy(tcp_option,pkt_data+sizeof(struct ethheader)+sizeof(struct ipv6header)+sizeof(struct tcpheader),tcp_option_length);    
                u_char *data1=(u_char *)malloc(header->caplen-sizeof(struct ethheader)-sizeof(struct ipv6header)-sizeof(struct tcpheader)-tcp_option_length);
                memcpy(data1,pkt_data+sizeof(struct ethheader)+sizeof(struct ipv6header)+sizeof(struct tcpheader)+tcp_option_length,header->caplen-sizeof(struct ethheader)-sizeof(struct ipv6header)-sizeof(struct tcpheader)-tcp_option_length);
                
                
                
                tcp_packet *tcp_pack=(tcp_packet *)(param->packet_buffer);
                tcp_pack->raw_data=raw_data;
                tcp_pack->raw_length=header->caplen;
                tcp_pack->eth=eth;
                tcp_pack->ip=(struct ipheader *)ipv6;
                tcp_pack->tcp=tcp;
                tcp_pack->tcp_option=tcp_option;
                tcp_pack->data=data1;
                param->packet_type=IPV6_TCP;
                u_int data_length1=(u_int)(header->caplen-sizeof(struct ethheader)-sizeof(struct ipv6header)-sizeof(struct tcpheader)-tcp_option_length);
                if(data_length1>0){
                    for (int i = 0; i < data_length1; i++)
                    {
                        printf("%02x ",data1[i]);
                    }
                    printf("转换为字符串为:%s\n",data1);
                }else{
                    printf("数据为空\n");
                }
                return;
                break;
            case IPPROTO_UDP:
                struct udpheader *udp=(struct udpheader *)malloc(sizeof(struct udpheader));
                memcpy(udp,pkt_data+sizeof(struct ethheader)+sizeof(struct ipv6header),sizeof(struct udpheader));

                u_char *data2=(u_char *)malloc(header->caplen-sizeof(struct ethheader)-sizeof(struct ipv6header)-sizeof(struct udpheader));
                memcpy(data2,pkt_data+sizeof(struct ethheader)+sizeof(struct ipv6header)+sizeof(struct udpheader),header->caplen-sizeof(struct ethheader)-sizeof(struct ipv6header)-sizeof(struct udpheader));
            
                udp_packet *udp_pack=(udp_packet *)(param->packet_buffer);
                udp_pack->raw_data=raw_data;
                udp_pack->raw_length=header->caplen;
                udp_pack->eth=eth;
                udp_pack->ip=(struct ipheader *)ipv6;
                udp_pack->udp=udp;
                udp_pack->data=data2;
                param->packet_type=IPV6_UDP;
                
                printf("UDP协议\n");
                printf("源端口:%d\n",ntohs(udp->uh_sport));
                printf("目的端口:%d\n",ntohs(udp->uh_dport));

                u_int data_length2=(u_int)(header->caplen-sizeof(struct ethheader)-sizeof(struct ipv6header)-sizeof(struct udpheader));
                if(data_length2>0){
                    for(int i=0;i<data_length2;i++){
                        printf("%02x ",data2[i]);
                    }
                    printf("转换为字符串为:%s\n",data2);
                }else{
                    printf("数据为空\n");
                }
                return;
                break;
            case IPPROTO_ICMP:
                struct icmpheader *icmp=(struct icmpheader *)malloc(sizeof(struct icmpheader));
                memcpy(icmp,pkt_data+sizeof(struct ethheader)+sizeof(struct ipv6header),sizeof(struct icmpheader));

                u_char *data3=(u_char *)malloc(header->caplen-sizeof(struct ethheader)-sizeof(struct ipv6header)-sizeof(struct icmpheader));
                memcpy(data3,pkt_data+sizeof(struct ethheader)+sizeof(struct ipv6header)+sizeof(struct icmpheader),header->caplen-sizeof(struct ethheader)-sizeof(struct ipv6header)-sizeof(struct icmpheader));

                icmp_packet *icmp_pack=(icmp_packet *)(param->packet_buffer);
                icmp_pack->raw_data=raw_data;
                icmp_pack->raw_length=header->caplen;
                icmp_pack->eth=eth;
                icmp_pack->ip=(struct ipheader *)ipv6;
                icmp_pack->icmp=icmp;
                icmp_pack->data=data3;
                param->packet_type=IPV6_ICMP;
                u_int data_length3=(u_int)(header->caplen-sizeof(struct ethheader)-sizeof(struct ipv6header)-sizeof(struct icmpheader));
                if(data_length3>0){
                    for(int i=0;i<data_length3;i++){
                        printf("%02x ",data3[i]);
                    }
                    printf("转换为字符串为:%s\n",data3);
                }else{
                    printf("数据为空\n");
                }
                printf("ICMP协议\n");
                break;
        }
    }else{
        printf("未知数据包\n");
    }
    raw_packet *raw_packet_data=(raw_packet *)param1;
    memcpy(raw_packet_data->data,pkt_data,header->caplen);
    raw_packet_data->length=header->caplen;
    if (header->caplen>buffer_size) {
        printf("捕获的数据不完整\n");
    }
    return;
}
void free_packet(u_char *packet1){
    packet_args *packet=(packet_args *)packet1;
    switch (packet->packet_type)
    {
    case IPV4_TCP:
        free(((tcp_packet *)(packet->packet_buffer))->eth);
        free(((tcp_packet *)(packet->packet_buffer))->ip);
        free(((tcp_packet *)(packet->packet_buffer))->ip_option);
        free(((tcp_packet *)(packet->packet_buffer))->tcp);
        free(((tcp_packet *)(packet->packet_buffer))->tcp_option);
        free(((tcp_packet *)(packet->packet_buffer))->data);
        free(((tcp_packet *)(packet->packet_buffer))->raw_data);
        break;
    case IPV4_UDP:
        free(((udp_packet *)(packet->packet_buffer))->eth);
        free(((udp_packet *)(packet->packet_buffer))->ip);
        free(((udp_packet *)(packet->packet_buffer))->ip_option);
        free(((udp_packet *)(packet->packet_buffer))->udp);
        free(((udp_packet *)(packet->packet_buffer))->data);
        free(((udp_packet *)(packet->packet_buffer))->raw_data);
        break;
    case IPV4_ICMP:
        free(((icmp_packet *)(packet->packet_buffer))->eth);
        free(((icmp_packet *)(packet->packet_buffer))->ip);
        free(((icmp_packet *)(packet->packet_buffer))->ip_option);
        free(((icmp_packet *)(packet->packet_buffer))->icmp);
        free(((icmp_packet *)(packet->packet_buffer))->data);
        free(((icmp_packet *)(packet->packet_buffer))->raw_data);
        break;
    case IPV6_TCP:
        free(((tcp_packet *)(packet->packet_buffer))->eth);
        free(((tcp_packet *)(packet->packet_buffer))->ip);
        free(((tcp_packet *)(packet->packet_buffer))->tcp);
        free(((tcp_packet *)(packet->packet_buffer))->tcp_option);
        free(((tcp_packet *)(packet->packet_buffer))->data);
        free(((tcp_packet *)(packet->packet_buffer))->raw_data);
        break;
    case IPV6_UDP:
        free(((udp_packet *)(packet->packet_buffer))->eth);
        free(((udp_packet *)(packet->packet_buffer))->ip);
        free(((udp_packet *)(packet->packet_buffer))->udp);
        free(((udp_packet *)(packet->packet_buffer))->data);
        free(((udp_packet *)(packet->packet_buffer))->raw_data);
        break;
    case IPV6_ICMP:
        free(((icmp_packet *)(packet->packet_buffer))->eth);
        free(((icmp_packet *)(packet->packet_buffer))->ip);
        free(((icmp_packet *)(packet->packet_buffer))->icmp);
        free(((icmp_packet *)(packet->packet_buffer))->data);
        free(((icmp_packet *)(packet->packet_buffer))->raw_data);
        break;
    
    case IPV4_TCP_VLAN:
        free(((tcp_packet_vlan *)(packet->packet_buffer))->eth);
        free(((tcp_packet_vlan *)(packet->packet_buffer))->ip);
        free(((tcp_packet_vlan *)(packet->packet_buffer))->ip_option);
        free(((tcp_packet_vlan *)(packet->packet_buffer))->tcp);
        free(((tcp_packet_vlan *)(packet->packet_buffer))->tcp_option);
        free(((tcp_packet_vlan *)(packet->packet_buffer))->data);
        free(((tcp_packet_vlan *)(packet->packet_buffer))->raw_data);
        break;
    case IPV4_UDP_VLAN:
        free(((udp_packet_vlan *)(packet->packet_buffer))->eth);
        free(((udp_packet_vlan *)(packet->packet_buffer))->ip);
        free(((udp_packet_vlan *)(packet->packet_buffer))->ip_option);
        free(((udp_packet_vlan *)(packet->packet_buffer))->udp);
        free(((udp_packet_vlan *)(packet->packet_buffer))->data);
        free(((udp_packet_vlan *)(packet->packet_buffer))->raw_data);
        break;
    case IPV4_ICMP_VLAN:
        free(((icmp_packet_vlan *)(packet->packet_buffer))->eth);
        free(((icmp_packet_vlan *)(packet->packet_buffer))->ip);
        free(((icmp_packet_vlan *)(packet->packet_buffer))->ip_option);
        free(((icmp_packet_vlan *)(packet->packet_buffer))->icmp);
        free(((icmp_packet_vlan *)(packet->packet_buffer))->data);
        free(((icmp_packet_vlan *)(packet->packet_buffer))->raw_data);
        break;
    case IPV6_TCP_VLAN:
        free(((tcp_packet_vlan *)(packet->packet_buffer))->eth);
        free(((tcp_packet_vlan *)(packet->packet_buffer))->ip);
        free(((tcp_packet_vlan *)(packet->packet_buffer))->tcp);
        free(((tcp_packet_vlan *)(packet->packet_buffer))->tcp_option);
        free(((tcp_packet_vlan *)(packet->packet_buffer))->data);
        free(((tcp_packet_vlan *)(packet->packet_buffer))->raw_data);
        break;
    case IPV6_UDP_VLAN:
        free(((udp_packet_vlan *)(packet->packet_buffer))->eth);
        free(((udp_packet_vlan *)(packet->packet_buffer))->ip);
        free(((udp_packet_vlan *)(packet->packet_buffer))->udp);
        free(((udp_packet_vlan *)(packet->packet_buffer))->data);
        free(((udp_packet_vlan *)(packet->packet_buffer))->raw_data);
        break;
    case IPV6_ICMP_VLAN:
        free(((icmp_packet_vlan *)(packet->packet_buffer))->eth);
        free(((icmp_packet_vlan *)(packet->packet_buffer))->ip);
        free(((icmp_packet_vlan *)(packet->packet_buffer))->icmp);
        free(((icmp_packet_vlan *)(packet->packet_buffer))->data);
        free(((icmp_packet_vlan *)(packet->packet_buffer))->raw_data);
        break;
    case ARP:
        free(((arp_packet *)(packet->packet_buffer))->eth);
        free(((arp_packet *)(packet->packet_buffer))->arp);
        free(((arp_packet *)(packet->packet_buffer))->raw_data);
        break;
    case ARP_VLAN:
        free(((arp_packet_vlan *)(packet->packet_buffer))->eth);
        free(((arp_packet_vlan *)(packet->packet_buffer))->arp);
        free(((arp_packet_vlan *)(packet->packet_buffer))->raw_data);
        break;
    default:
        break;
    }
}